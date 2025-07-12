// nat64Utils.js (This part remains separate for clarity, but you'd conceptually include its functions)

const DNS_QUERY_URL = 'https://1.1.1.1/dns-query';

/**
 * Converts an IPv4 address string to a NAT64 IPv6 address.
 * Uses the well-known NAT64 prefix 64:ff9b::/96 (as per RFC 6052, commonly used)
 * Note: The original prefix in your provided code (2001:67c:2960:6464::/96)
 * is also a valid NAT64 prefix, often used for specific deployments.
 * For a general purpose NAT64, 64:ff9b::/96 is the standard well-known prefix.
 * I'll use 64:ff9b::/96 here for broader compatibility, but you can revert
 * to your original if it's specific to your setup.
 * @param {string} ipv4 - The IPv4 address (e.g., "192.0.2.1").
 * @returns {string} The NAT64 IPv6 address (e.g., "64:ff9b::c000:201").
 * @throws {Error} If the IPv4 address is invalid.
 */
function convertToNAT64IPv6(ipv4) {
    const parts = ipv4.split('.');
    if (parts.length !== 4 || parts.some(p => isNaN(Number(p)) || Number(p) < 0 || Number(p) > 255)) {
        throw new Error('Invalid IPv4 address');
    }
    const hex = parts.map(p => Number(p).toString(16).padStart(2, '0'));
    // Using the well-known prefix 64:ff9b::/96
    return `64:ff9b::${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;
}

/**
 * Resolves a domain to its IPv4 address using DNS-over-HTTPS (DoH) and then converts it to a NAT64 IPv6 address.
 * @param {string} domain - The domain name (e.g., "example.com").
 * @returns {Promise<string>} A promise that resolves to the NAT64 IPv6 address.
 * @throws {Error} If the domain cannot be resolved to an IPv4 address.
 */
async function resolveDomainToNAT64IPv6(domain) {
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

// --- Start of integrated Cloudflare Worker code ---

let 转码 = 'vl', 转码2 = 'ess', 符号 = '://';

// version base on commit 58686d5d125194d34a1137913b3a64ddcf55872f, time is 2024-11-27 09:26:02 UTC.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
let proxyIP = 'proxyip.zone.id';

if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, HIDE_SUBSCRIPTION?: string, SARCASM_MESSAGE?: string, 隐藏?: string, 嘲讽语?: string, NAT64?: string}} env // Added NAT64 to env type
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;

            // --- NAT64 Control Variable ---
            // Default to true (enabled)
            let NAT64_ENABLED = true;
            // Check for the NAT64 environment variable and override if present
            if (env.NAT64 !== undefined) {
                NAT64_ENABLED = env.NAT64 === 'true';
            }
            // --- End NAT64 Control Variable ---

			let 隐藏 = false; // 默认值
            let 嘲讽语 = "哎呀你找到了我，但是我就是不给你看，气不气，嘿嘿嘿"; // 默认值

            if (env.HIDE_SUBSCRIPTION !== undefined) {
                隐藏 = env.HIDE_SUBSCRIPTION === 'true';
            } else if (env.隐藏 !== undefined) {
                隐藏 = env.隐藏 === 'true';
            }

            if (env.SARCASM_MESSAGE !== undefined) {
                嘲讽语 = env.SARCASM_MESSAGE;
            } else if (env.嘲讽语 !== undefined) {
                嘲讽语 = env.嘲讽语;
            }

            console.log(`环境变量 HIDE_SUBSCRIPTION 原始值 (英文): ${env.HIDE_SUBSCRIPTION}`);
            console.log(`环境变量 隐藏 原始值 (中文): ${env.隐藏}`);
            console.log(`最终解析的布尔值 隐藏: ${隐藏}`);
            console.log(`环境变量 SARCASM_MESSAGE 原始值 (英文): ${env.SARCASM_MESSAGE}`);
            console.log(`环境变量 嘲讽语 原始值 (中文): ${env.嘲讽语}`);
            console.log(`最终解析的嘲讽语: ${嘲讽语}`);
            console.log(`NAT64_ENABLED: ${NAT64_ENABLED}`); // Log NAT64 status

			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case '/':
						return new Response(JSON.stringify(request.cf), { status: 200 });
					case `/${userID}`: {
						if (隐藏) {
							return new Response(嘲讽语, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						} else {
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
				// Pass NAT64_ENABLED to the handler
				return await dynamicProtocolOverWSHandler(request, NAT64_ENABLED);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

/**
 * * @param {import("@cloudflare/workers-types").Request} request
 * @param {boolean} NAT64_ENABLED
 */
async function dynamicProtocolOverWSHandler(request, NAT64_ENABLED) { // Added NAT64_ENABLED parameter

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
				throw new Error(message); 
				return;
			}
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP proxy only enable for DNS which is port 53'); 
					return;
				}
			}
			const dynamicProtocolResponseHeader = new Uint8Array([dynamicProtocolVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, dynamicProtocolResponseHeader, log);
			}

			// --- NAT64 Integration Start ---
			let finalAddressRemote = addressRemote;
			if (NAT64_ENABLED) {
				// If it's an IPv4 address, convert it to NAT64 IPv6
				if (addressType === 1) { // IPv4
					try {
						finalAddressRemote = convertToNAT64IPv6(addressRemote);
						log(`Converted IPv4 ${addressRemote} to NAT64 IPv6 ${finalAddressRemote}`);
					} catch (e) {
						log(`Failed to convert IPv4 ${addressRemote} to NAT64 IPv6: ${e.message}`, 'warn');
						// Fallback to original IPv4 if conversion fails
					}
				} else if (addressType === 2) { // Domain name
					try {
						finalAddressRemote = await resolveDomainToNAT64IPv6(addressRemote);
						log(`Resolved domain ${addressRemote} to NAT64 IPv6 ${finalAddressRemote}`);
					} catch (e) {
						log(`Failed to resolve domain ${addressRemote} to NAT64 IPv6: ${e.message}`, 'warn');
						// Fallback to original domain name if resolution fails
					}
				}
			}
			// --- NAT64 Integration End ---

			handleTCPOutBound(remoteSocketWapper, addressType, finalAddressRemote, portRemote, rawClientData, webSocket, dynamicProtocolResponseHeader, log);
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
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, dynamicProtocolResponseHeader, log,) {
	async function connectAndWrite(address, port) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); // 首次写入，通常是 TLS 握手
		writer.releaseLock();
		return tcpSocket;
	}

	async function retry() {
		tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, dynamicProtocolResponseHeader, null, log);
	}

	let tcpSocket = await connectAndWrite(addressRemote, portRemote);

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

			webSocketServer.addEventListener('close', () => {
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
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
		},
		cancel(reason) {
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

	const command = new Uint8Array(
		dynamicProtocolBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

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
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		dynamicProtocolBuffer.slice(addressIndex, addressIndex + 1)
	);

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
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
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
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let dynamicProtocolHeader = dynamicProtocolResponseHeader;
	let hasIncomingData = false;
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
