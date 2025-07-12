// nat64Utils.js (Integrated)
const DNS_QUERY_URL = 'https://1.1.1.1/dns-query';

/**
 * Converts an IPv4 address string to a NAT64 IPv6 address.
 * Uses the well-known NAT64 prefix 2001:67c:2960:6464::/96
 * @param {string} ipv4 - The IPv4 address (e.g., "192.0.2.1").
 * @returns {string} The NAT64 IPv6 address (e.g., "[2001:67c:2960:6464::c000:201]").
 * @throws {Error} If the IPv4 address is invalid.
 */
function convertToNAT64IPv6(ipv4) {
    const parts = ipv4.split('.');
    if (parts.length !== 4) {
        throw new Error('Invalid IPv4 address');
    }
    const hex = parts.map(p => Number(p).toString(16).padStart(2, '0'));
    return `2001:67c:2960:6464::${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;
}

/**
 * Resolves a domain to its IPv4 address and then converts it to a NAT64 IPv6 address.
 * Uses DNS-over-HTTPS (DoH) to query for the A record.
 * @param {string} domain - The domain name (e.g., "example.com").
 * @returns {Promise<string>} A promise that resolves to the NAT64 IPv6 address.
 * @throws {Error} If the domain cannot be resolved to an IPv4 address.
 */
async function getIPv6ProxyAddress(domain) {
    try {
        const response = await fetch(`${DNS_QUERY_URL}?name=${domain}&type=A`, {
            headers: { 'Accept': 'application/dns-json' }
        });
        const data = await response.json();
        const ipv4Record = data.Answer?.find(x => x.type === 1); // Type 1 is A record (IPv4)

        if (!ipv4Record) {
            throw new Error(`Could not resolve IPv4 address for domain: ${domain}`);
        }
        return convertToNAT64IPv6(ipv4Record.data);
    } catch (error) {
        console.error('Error resolving domain with DoH:', error);
        throw new Error(`Failed to get NAT64 IPv6 address for ${domain}`);
    }
}
// End of nat64Utils.js integration

let 转码 = 'vl', 转码2 = 'ess', 符号 = '://';

// version base on commit 58686d5d125194d34a1137913b3a64ddcf55872f, time is 2024-11-27 09:26:02 UTC.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

let proxyIP = 'proxyip.zone.id';

if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, HIDE_SUBSCRIPTION?: string, SARCASM_MESSAGE?: string, 隐藏?: string, 嘲讽语?: string, NAT64?: string}} env // 变量名已更新为 NAT64
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;

            let 隐藏 = false; // 默认值
            let 嘲讽语 = "哎呀你找到了我，但是我就是不给你看，气不气，嘿嘿嘿"; // 默认值
            let enableNAT64 = true; // NAT64开关，默认打开

            if (env.HIDE_SUBSCRIPTION !== undefined) {
                隐藏 = env.HIDE_SUBSCRIPTION === 'true';
            } else if (env.隐藏 !== undefined) { // 尝试读取中文变量名
                隐藏 = env.隐藏 === 'true';
            }

            if (env.SARCASM_MESSAGE !== undefined) {
                嘲讽语 = env.SARCASM_MESSAGE;
            } else if (env.嘲讽语 !== undefined) { // 尝试读取中文变量名
                嘲讽语 = env.嘲讽语;
            }

            // --- 最终修复点：更健壮的 NAT64 环境变量解析 ---
            // 如果 env.NAT64 这个环境变量被设置了，就用它的值来决定 enableNAT64
            // 否则，保持 enableNAT64 的默认值 (true)
            if (env.NAT64 !== undefined) {
                enableNAT64 = env.NAT64 === 'true'; // 只有当字符串严格等于 "true" 时才为 true，否则为 false
            }
            // --- 最终修复点结束 ---

            // --- **调试日志：请留意这里** ---
            console.log(`环境变量 HIDE_SUBSCRIPTION 原始值 (英文): ${env.HIDE_SUBSCRIPTION}`);
            console.log(`环境变量 隐藏 原始值 (中文): ${env.隐藏}`);
            console.log(`最终解析的布尔值 隐藏: ${隐藏}`);
            console.log(`环境变量 SARCASM_MESSAGE 原始值 (英文): ${env.SARCASM_MESSAGE}`);
            console.log(`环境变量 嘲讽语 原始值 (中文): ${env.嘲讽语}`);
            console.log(`最终解析的嘲讽语: ${嘲讽语}`);
            console.log(`环境变量 NAT64 原始值: ${env.NAT64}`); // 日志中也已更新
            console.log(`最终解析的布尔值 enableNAT64: ${enableNAT64}`);
            // --- **调试日志结束** ---


			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case '/':
						return new Response(JSON.stringify(request.cf), { status: 200 });
					case `/${userID}`: {
						// 根据 隐藏 变量决定是否显示订阅配置
						if (隐藏) {
							// 隐藏模式启动，给个“惊喜”
							return new Response(嘲讽语, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						} else {
							// 正常展示，无需遮掩
							const dynamicProtocolConfig = getDynamicProtocolConfig(userID, request.headers.get('Host'));
							return new Response(`${dynamicProtocolConfig}`, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						}
					}
					default:
						return new Response('Not found', { status: 404 });
				}
			} else {
				// 是 WebSocket 请求？那就去处理“秘密隧道”吧
				return await dynamicProtocolOverWSHandler(request, enableNAT64); // 传递 enableNAT64
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			// 哎呀，出错了，直接把错误信息吐出来
			return new Response(e.toString());
		}
	},
};

/**
 * * @param {import("@cloudflare/workers-types").Request} request
 * @param {boolean} enableNAT64 // 接收 enableNAT64 变量
 */
async function dynamicProtocolOverWSHandler(request, enableNAT64) {

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

	// ws --> remote (数据流向：从 WebSocket 到远程目标)
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				// 如果是 DNS 查询，特殊处理
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				// 远程连接已建立，直接写入数据
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			// 解析协议头部，这是“解密”的关键一步
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
				// 出错？直接中断，不给机会
				throw new Error(message); 
			}
			// 如果是 UDP 但不是 DNS 端口，就拒绝
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new new Error('UDP proxy only enable for DNS which is port 53'); 
				}
			}
			// 响应头部，版本信息
			const dynamicProtocolResponseHeader = new Uint8Array([dynamicProtocolVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, dynamicProtocolResponseHeader, log);
			}
			// 处理 TCP 出站连接，真正的“连接世界”
			await handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, dynamicProtocolResponseHeader, log, enableNAT64);
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
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {number} addressType The remote address type to connect to.
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} dynamicProtocolResponseHeader The dynamicProtocol response header.
 * @param {function} log The logging function.
 * @param {boolean} enableNAT64 // 新增：是否启用 NAT64
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, dynamicProtocolResponseHeader, log, enableNAT64) {
    let targetAddress = addressRemote;
    let isNAT64Used = false;

    if (enableNAT64) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(addressRemote)) {
            // It's an IPv4 address, convert to NAT64 IPv6
            try {
                targetAddress = convertToNAT64IPv6(addressRemote);
                isNAT64Used = true;
                log(`Converted IPv4 ${addressRemote} to NAT64 IPv6: ${targetAddress}`);
            } catch (error) {
                console.warn(`Could not convert IPv4 ${addressRemote} to NAT64 IPv6: ${error.message}, falling back to proxyIP.`);
                targetAddress = proxyIP || addressRemote; // Fallback to proxyIP or original if conversion fails
                isNAT64Used = false;
            }
        } else if (!addressRemote.includes(':')) {
            // It's a domain name, resolve to NAT64 IPv6
            try {
                targetAddress = await getIPv6ProxyAddress(addressRemote);
                isNAT64Used = true;
                log(`Resolved domain ${addressRemote} to NAT64 IPv6: ${targetAddress}`);
            } catch (error) {
                console.warn(`Could not resolve domain ${addressRemote} to NAT64 IPv6: ${error.message}, falling back to proxyIP.`);
                targetAddress = proxyIP || addressRemote; // Fallback to proxyIP or original if resolution fails
                isNAT64Used = false;
            }
        }
        // If it's already an IPv6 address, no NAT64 conversion is needed, use targetAddress = addressRemote (default)
    } else {
        log(`NAT64 is disabled. Connecting to ${addressRemote}:${portRemote} or proxyIP.`);
    }

	async function connectAndWrite(address, port) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		// 建立与远程目标的 TCP 连接，这是数据的“出口”
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connecting to ${address}:${port} (NAT64: ${isNAT64Used})`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); // 首次写入，通常是 TLS 握手
		writer.releaseLock();
		return tcpSocket;
	}

	// 如果 CF 的 TCP 连接没有收到数据，就尝试“重定向”IP
	async function retry() {
        let retryAddress = proxyIP || addressRemote; // Always fallback to proxyIP if the first attempt fails or if NAT64 is off.
        log(`Retrying connection to ${retryAddress}:${portRemote}`);
		tcpSocket = await connectAndWrite(retryAddress, portRemote);
		// 不管重试成功与否，都要关闭 WebSocket
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, dynamicProtocolResponseHeader, null, log);
	}

	let tcpSocket = await connectAndWrite(targetAddress, portRemote);

	// 当远程 Socket 准备好后，将其“传递”给 WebSocket
	// remote--> ws (数据流向：从远程目标到 WebSocket)
	remoteSocketToWS(tcpSocket, webSocket, dynamicProtocolResponseHeader, retry, log);
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
				// 客户端发来关闭请求，需要服务器也关闭
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
			// 处理 WebSocket 0-RTT 的早期数据
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
			// 如果 WebSocket 可以停止读取（当流满时），我们可以实现背压
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},
		cancel(reason) {
			// 流被取消了，多半是出问题了
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
	// 协议头部解析，这是“身份验证”与“路由”的关键
	if (dynamicProtocolBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}
	const version = new Uint8Array(dynamicProtocolBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	// 校验用户 ID，确保是“自家兄弟”
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
	// 端口是大端序
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		dynamicProtocolBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1--> ipv4  addressLength =4
	// 2--> domain name
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
	// remote--> ws (数据流向：从远程目标到 WebSocket)
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let dynamicProtocolHeader = dynamicProtocolResponseHeader;
	let hasIncomingData = false; // 检查远程 Socket 是否有传入数据
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
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (dynamicProtocolHeader) {
						// 首次发送带头部信息
						webSocket.send(await new Blob([dynamicProtocolHeader, chunk]).arrayBuffer());
						dynamicProtocolHeader = null;
					} else {
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
				},
				abort(reason) {
					console.error(
						`remoteConnection!.readable abort`, reason);
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

	// 如果 CF 连接 socket 没有收到任何数据，就尝试重试（如果重试函数存在）
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
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
		// Base64 解码，处理 URL 安全字符
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
	// UUID 格式校验，确保是“合法身份”
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
		// 安全关闭 WebSocket，避免“意外”
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
	// DNS 查询处理，始终使用硬编码的 DNS 服务器
	try {
		const dnsServer = '8.8.4.4'; 
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

/**
 * * @param {string} userID 
 * @param {string | null} hostName
 * @returns {string}
 */
function getDynamicProtocolConfig(userID, hostName) {
	// 生成 V2Ray 和 Clash-Meta 配置，这是“订阅信息”的载体
	const protocol = 转码 + 转码2; 
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
################################################################
`;
}
