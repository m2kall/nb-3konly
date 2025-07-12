let 转码 = 'vl', 转码2 = 'ess', 符号 = '://';

// version base on commit 58686d5d125194d34a1137913b3a64ddcf55872f, time is 2024-11-27 09:26:02 UTC.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

let proxyIP = '';

// NAT64 默认开启
let NAT64 = true; 

if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, NAT64: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;
            // NAT64 默认开启，不再从环境变量读取（如需可配置，请取消注释下一行，并确保 env.NAT64 是 'true' 或 'false' 字符串）
            // NAT64 = (env.NAT64 === 'true'); 

			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case '/':
						return new Response(JSON.stringify(request.cf), { status: 200 });
					case `/${userID}`: {
						const dynamicProtocolConfig = getDynamicProtocolConfig(userID, request.headers.get('Host'));
						return new Response(`${dynamicProtocolConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					}
					default:
						return new Response('Not found', { status: 404 });
				}
			} else {
				return await dynamicProtocolOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};




/**
 * * @param {import("@cloudflare/workers-types").Request} request
 */
async function dynamicProtocolOverWSHandler(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				addressType,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				dynamicProtocolVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processDynamicProtocolHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '
				} `;
			if (hasError) {
				// controller.error(message);
				throw new Error(message); // cf seems has bug, controller.error will not end stream
				// webSocket.close(1000, message);
				return;
			}
			// if UDP but port not DNS port, close it
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					// controller.error('UDP proxy only enable for DNS which is port 53');
					throw new Error('UDP proxy only enable for DNS which is port 53'); // cf seems has bug, controller.error will not end stream
					return;
				}
			}
			// ["version", "附加信息长度 N"]
			const dynamicProtocolResponseHeader = new Uint8Array([dynamicProtocolVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, dynamicProtocolResponseHeader, log);
			}
			handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, dynamicProtocolResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections with a priority of Direct -> NAT64 -> ProxyIP.
 *
 * @param {any} remoteSocketWapper Object to hold the established remote socket.
 * @param {number} addressType The remote address type to connect to. (unused in this refined logic but kept for context)
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write to the socket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to communicate with the client.
 * @param {Uint8Array} dynamicProtocolResponseHeader The VL response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>}
 */
async function handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, dynamicProtocolResponseHeader, log) {
    let tcpSocket = null;
    let connected = false;

    /**
     * Attempts to connect to a given address and port, and writes initial data.
     * @param {string} address The target address.
     * @param {number} port The target port.
     * @returns {Promise<import("@cloudflare/workers-types").Socket>} The connected TCP socket.
     */
    async function attemptConnect(address, port) {
        const socket = connect({ hostname: address, port: port });
        remoteSocketWapper.value = socket; // Update the wrapper with the potential socket
        await socket.opened; // Wait for the connection to be established
        const writer = socket.writable.getWriter();
        await writer.write(rawClientData); // Write the initial client data
        writer.releaseLock();
        return socket;
    }

    // --- 1. 尝试直连 ---
    try {
        log(`Attempting direct connection to ${addressRemote}:${portRemote}...`);
        tcpSocket = await attemptConnect(addressRemote, portRemote);
        connected = true;
        log(`Direct connect to ${addressRemote}:${portRemote} successful.`);
    } catch (e) {
        log(`Direct connect to ${addressRemote}:${portRemote} failed: ${e.message}`);
    }

    // --- 2. 直连不通时，尝试 NAT64 ---
    if (!connected && NAT64) {
        try {
            let natTarget = null;
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(addressRemote)) { // 是 IPv4 地址
                natTarget = convertToNAT64IPv6(addressRemote);
                log(`Converted IPv4 ${addressRemote} to NAT64 IPv6 ${natTarget}.`);
            } else if (addressRemote.includes(':')) { // 已经是 IPv6 地址，NAT64 无需处理
                log(`Target ${addressRemote} is already IPv6. Skipping NAT64.`);
                // 这里不抛出错误，因为可能直连 IPv6 失败，仍希望尝试 ProxyIP
            } else { // 是域名，尝试解析为 IPv4 并进行 NAT64 转换
                log(`Resolving domain ${addressRemote} for NAT64...`);
                natTarget = await getIPv6ProxyAddress(addressRemote);
                log(`Resolved ${addressRemote} to NAT64 IPv6 ${natTarget}.`);
            }

            if (natTarget) { // 如果成功获得了 NAT64 目标地址
                const cleanedNatTarget = natTarget.replace(/[\"'`]+/g, ''); // 清理可能引入的引号
                log(`Attempting NAT64 connection to ${cleanedNatTarget}:${portRemote} (original: ${addressRemote})...`);
                tcpSocket = await attemptConnect(cleanedNatTarget, portRemote);
                connected = true;
                log(`NAT64 connect to ${cleanedNatTarget}:${portRemote} successful.`);
            }
        } catch (e) {
            log(`NAT64 connect to ${addressRemote}:${portRemote} failed: ${e.message}`);
        }
    }

    // --- 3. NAT64 不通时，尝试 proxyIP 兜底 ---
    if (!connected && proxyIP) {
        try {
            log(`Attempting fallback proxyIP connection to ${proxyIP}:${portRemote} (original: ${addressRemote})...`);
            tcpSocket = await attemptConnect(proxyIP, portRemote);
            connected = true;
            log(`ProxyIP connect to ${proxyIP}:${portRemote} successful.`);
        } catch (e) {
            log(`ProxyIP connect to ${proxyIP}:${portRemote} failed: ${e.message}`);
        }
    }

    // --- 检查是否成功连接 ---
    if (!connected || !tcpSocket) {
        throw new Error(`Failed to establish any outbound connection to ${addressRemote}:${portRemote}.`);
    }

    // --- 建立隧道连接 (如果成功) ---
    // no matter retry success or not, close websocket
    tcpSocket.closed.catch(error => {
        console.log('tcpSocket closed error', error);
    }).finally(() => {
        safeCloseWebSocket(webSocket);
    });
    
    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    remoteSocketToWS(tcpSocket, webSocket, dynamicProtocolResponseHeader, null, log);
}

/**
 * * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader for ws 0rtt
 * @param {(info: string)=> void} log for ws 0rtt
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});

			// The event means that the client closed the client -> server stream.
			// However, the server -> client stream is still open until you call close() on the server side.
			// The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
			webSocketServer.addEventListener('close', () => {
				// client send close, need close server
				// if stream is cancel, skip controller.close
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			}
			);
			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			}
			);
			// for ws 0rtt
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
			// if ws can stop read if stream is full, we can implement backpressure
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},
		cancel(reason) {
			// 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
			// 2. if readableStream is cancel, all controller.close/enqueue need skip,
			// 3. but from testing controller.error still work even if readableStream is cancel
			if (readableStreamCancel) {
				return;
			}
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;

}

// https://xtls.github.io/development/protocols/dynamicProtocol.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * * @param { ArrayBuffer} dynamicProtocolBuffer 
 * @param {string} userID 
 * @returns 
 */
function processDynamicProtocolHeader(
	dynamicProtocolBuffer,
	userID
) {
	if (dynamicProtocolBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}
	const version = new Uint8Array(dynamicProtocolBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	if (stringify(new Uint8Array(dynamicProtocolBuffer.slice(1, 17))) === userID) {
		isValidUser = true;
	}
	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(dynamicProtocolBuffer.slice(17, 18))[0];
	//skip opt for now

	const command = new Uint8Array(
		dynamicProtocolBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = dynamicProtocolBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		dynamicProtocolBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1--> ipv4  addressLength =4
	// 2--> domain name addressLength=addressBuffer[1]
	// 3--> ipv6  addressLength =16
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				dynamicProtocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				dynamicProtocolBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				dynamicProtocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				dynamicProtocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		dynamicProtocolVersion: version,
		isUDP,
	};
}


/**
 * * @param {import("@cloudflare/workers-types").Socket} remoteSocket 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} dynamicProtocolResponseHeader 
 * @param {(() => Promise<void>) | null} retry
 * @param {*} log 
 */
async function remoteSocketToWS(remoteSocket, webSocket, dynamicProtocolResponseHeader, retry, log) {
	// remote--> ws
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let dynamicProtocolHeader = dynamicProtocolResponseHeader;
	let hasIncomingData = false; // check if remoteSocket has incoming data
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				/**
				 * * @param {Uint8Array} chunk 
				 * @param {*} controller 
				 */
				async write(chunk, controller) {
					hasIncomingData = true;
					// remoteChunkCount++;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (dynamicProtocolHeader) {
						webSocket.send(await new Blob([dynamicProtocolHeader, chunk]).arrayBuffer());
						dynamicProtocolHeader = null;
					} else {
						// seems no need rate limit this, CF seems fix this??..
						// if (remoteChunkCount > 20000) {
						// 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
						// 	await delay(1);
						// }
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
					// safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	// retry logic has been moved to handleTCPOutBound, no longer needed here
}

/**
 * * @param {string} base64Str 
 * @returns 
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		// go use modified Base64 for URL rfc4648 which js atob not support
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

/**
 * This is not real UUID validation
 * @param {string} uuid 
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Normally, WebSocket will not has exceptions when close.
 * @param {import("@cloudflare/workers-types").WebSocket} socket
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}

/**
 * * @param {ArrayBuffer} udpChunk 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} dynamicProtocolResponseHeader 
 * @param {(string)=> void} log 
 */
async function handleDNSQuery(udpChunk, webSocket, dynamicProtocolResponseHeader, log) {
	// no matter which DNS server client send, we alwasy use hard code one.
	// beacsue someof DNS server is not support DNS over TCP
	try {
		const dnsServer = '8.8.4.4'; // change to 1.1.1.1 after cf fix connect own ip bug
		const dnsPort = 53;
		/** @type {ArrayBuffer | null} */
		let dynamicProtocolHeader = dynamicProtocolResponseHeader;
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = connect({
			hostname: dnsServer,
			port: dnsPort,
		});

		log(`connected to ${dnsServer}:${dnsPort}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WS_READY_STATE_OPEN) {
					if (dynamicProtocolHeader) {
						webSocket.send(await new Blob([dynamicProtocolHeader, chunk]).arrayBuffer());
						dynamicProtocolHeader = null;
					} else {
						webSocket.send(chunk);
					}
				}
			},
			close() {
				log(`dns server(${dnsServer}) tcp is close`);
			},
			abort(reason) {
				console.error(`dns server(${dnsServer}) tcp is abort`, reason);
			},
		}));
	} catch (error) {
		console.error(
			`handleDNSQuery have exception, error: ${error.message}`
		);
	}
}

/* ---------- NAT64 工具 ---------- */
function convertToNAT64IPv6(ipv4) {
  const parts = ipv4.split('.');
  if (parts.length !== 4) throw new Error('无效的IPv4地址');
  const hex = parts.map(p => Number(p).toString(16).padStart(2, '0'));
  return `[2001:67c:2960:6464::${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
}

async function getIPv6ProxyAddress(domain) {
  const r = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
    headers: { 'Accept': 'application/dns-json' }
  });
  const j = await r.json();
  const a = j.Answer?.find(x => x.type === 1);
  if (!a) throw new Error('无法解析域名的IPv4地址');
  return convertToNAT64IPv6(a.data);
}

/**
 * * @param {string} userID 
 * @param {string | null} hostName
 * @returns {string}
 */
function getDynamicProtocolConfig(userID, hostName) {
	const protocol = 转码 + 转码2; // 使用拼接的协议名
	const dynamicProtocolMain = 
	`${protocol}${符号}${userID}@${hostName}:443`+
	`?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
	
	return `
################################################################
v2ray
---------------------------------------------------------------
${dynamicProtocolMain}
---------------------------------------------------------------
################################################################
clash-meta
---------------------------------------------------------------
- type: ${转码 + 转码2}
  name: ${hostName}
  server: ${hostName}
  port: 443
  uuid: ${userID}
  network: ws
  tls: true
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
    path: "/?ed=2048"
    headers:
      host: ${hostName}
---------------------------------------------------------------
# 配置说明:
# NAT64 功能已默认开启。
# 在直连失败时会尝试通过 NAT64 转换 IPv4 地址并连接，
# 之后如果 NAT64 仍不通，则会尝试使用 proxyIP。
################################################################
`;
}
