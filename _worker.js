let 转码 = 'vl', 转码2 = 'ess', 符号 = '://';

// @ts-ignore
import { connect } from 'cloudflare:sockets';

// IMPORTANT: Replace with your actual UUID.
// If you set an environment variable named 'UUID' in Cloudflare,
// that will override this value.
let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

let proxyIP = ''; // Optional: Set an environment variable 'PROXYIP' to use.

// The mocking message displayed when the subscription page is hidden.
let 嘲讽语 = "哎呀你找到了我，但是我就是不给你看，气不气，嘿嘿嘿";


if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

export default {
	/**
	 * Main entry point for the Worker.
	 * @param {import("@cloudflare/workers-types").Request} request The incoming request.
	 * @param {{UUID: string, PROXYIP: string, HIDE_SUBSCRIPTION: string}} env Environment variables configured in Cloudflare.
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx The execution context.
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			// Override default userID/proxyIP with environment variables if they exist.
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;

            // CONTROL VARIABLE FOR SUBSCRIPTION VISIBILITY:
            // Reads the 'HIDE_SUBSCRIPTION' environment variable.
            // If HIDE_SUBSCRIPTION is "true" (case-insensitive), it becomes boolean true.
            // Otherwise (if "false", undefined, or anything else), it defaults to boolean false (visible).
            const hideSubscriptionPage = (env.HIDE_SUBSCRIPTION || 'false').toLowerCase() === 'true';

			const upgradeHeader = request.headers.get('Upgrade');

			// Handle non-WebSocket requests (HTTP requests to your worker).
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case '/':
						// Root path: Respond with Cloudflare request properties (for debugging/info).
						return new Response(JSON.stringify(request.cf), { status: 200 });
					case `/${userID}`: {
						// This is the specific path for your subscription page.
						// Its behavior is controlled by the 'hideSubscriptionPage' variable.
						if (hideSubscriptionPage) {
							// If hideSubscriptionPage is true, return the mocking message.
							return new Response(嘲讽语, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						} else {
							// If hideSubscriptionPage is false (default), return the subscription configuration.
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
						// Any other path not matching root or UUID will return 404 Not Found.
						return new Response('Not found', { status: 404 });
				}
			} else {
				// Handle WebSocket upgrade requests for proxy functionality.
				return await dynamicProtocolOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			// Catch and return any errors as a response.
			return new Response(e.toString());
		}
	},
};

---

## Helper Functions (Unchanged)

```javascript
/**
 * Handles dynamic protocol over WebSocket, forwarding traffic.
 * @param {import("@cloudflare/workers-types").Request} request The incoming WebSocket upgrade request.
 */
async function dynamicProtocolOverWSHandler(request) {
	// Create a WebSocket pair for communication.
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept(); // Accept the WebSocket connection.

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

	// Pipe data from WebSocket to the remote target.
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				// Special handling for DNS queries.
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				// If remote connection is established, write data directly.
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			// Process the dynamic protocol header to get target info.
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
				// If header processing fails, throw an error.
				throw new Error(message); 
			}
			// UDP proxy is currently only enabled for DNS (port 53).
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP proxy only enable for DNS which is port 53'); 
				}
			}
			// Prepare the response header.
			const dynamicProtocolResponseHeader = new Uint8Array([dynamicProtocolVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, dynamicProtocolResponseHeader, log);
			}
			// Handle outbound TCP connection.
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

	// Return the WebSocket response.
	return new Response(null, {
		status: 101, // 101 Switching Protocols for WebSocket handshake.
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections.
 * @param {any} remoteSocket Wrapper for the remote socket.
 * @param {number} addressType The remote address type to connect to.
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write initially.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket data to.
 * @param {Uint8Array} dynamicProtocolResponseHeader The dynamic protocol response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>}
 */
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, dynamicProtocolResponseHeader, log,) {
	async function connectAndWrite(address, port) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		// Establish a TCP connection to the remote target.
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter()
		await writer.write(rawClientData); // Write initial client data (e.g., TLS handshake).
		writer.releaseLock();
		return tcpSocket;
	}

	// Retry mechanism if the initial CF TCP connection receives no data.
	async function retry() {
		let tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, dynamicProtocolResponseHeader, null, log);
	}

	let tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// Pipe data from the remote socket back to the WebSocket.
	remoteSocketToWS(tcpSocket, webSocket, dynamicProtocolResponseHeader, retry, log);
}

/**
 * Creates a readable stream from a WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader For WebSocket 0-RTT.
 * @param {(info: string)=> void} log Logging function.
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
			});
			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			});
			// Handle early data for WebSocket 0-RTT.
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
			// This could be used for backpressure if the WebSocket could stop reading.
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
 * Processes the dynamic protocol header for connection details.
 * @param {ArrayBuffer} dynamicProtocolBuffer The incoming data buffer.
 * @param {string} userID The expected user ID for validation.
 * @returns {object} Parsed header details or an error object.
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
	// Validate User ID.
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

	// 0x01 TCP, 0x02 UDP, 0x03 MUX
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
	// Port is Big-Endian.
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		dynamicProtocolBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1: IPv4, 2: Domain Name, 3: IPv6
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
 * Pipes data from a remote socket to a WebSocket.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection.
 * @param {ArrayBuffer} dynamicProtocolResponseHeader The dynamic protocol response header.
 * @param {(() => Promise<void>) | null} retry Optional retry function.
 * @param {*} log Logging function.
 */
async function remoteSocketToWS(remoteSocket, webSocket, dynamicProtocolResponseHeader, retry, log) {
	let dynamicProtocolHeader = dynamicProtocolResponseHeader;
	let hasIncomingData = false; // Check if remote socket has incoming data.
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() { },
				/**
				 * @param {Uint8Array} chunk 
				 */
				async write(chunk, controller) {
					hasIncomingData = true;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error('webSocket.readyState is not open, maybe close');
					}
					if (dynamicProtocolHeader) {
						// Send initial data with header.
						webSocket.send(await new Blob([dynamicProtocolHeader, chunk]).arrayBuffer());
						dynamicProtocolHeader = null;
					} else {
						// Send subsequent data directly.
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
			console.error(`remoteSocketToWS has exception `, error.stack || error);
			safeCloseWebSocket(webSocket);
		});

	// If no incoming data and retry function exists, try retrying.
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

/**
 * Converts a Base64 string to an ArrayBuffer.
 * @param {string} base64Str 
 * @returns {object} Object containing earlyData ArrayBuffer or an error.
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/'); // Handle URL-safe Base64.
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

/**
 * Basic validation for UUID format.
 * @param {string} uuid 
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Safely closes a WebSocket connection.
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
 * Handles DNS queries, hardcoding to 8.8.4.4 for now.
 * @param {ArrayBuffer} udpChunk UDP data chunk.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket WebSocket instance.
 * @param {ArrayBuffer} dynamicProtocolResponseHeader Dynamic protocol response header.
 * @param {(string)=> void} log Logging function.
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
		console.error(`handleDNSQuery have exception, error: ${error.message}`);
	}
}

/**
 * Generates V2Ray and Clash-Meta subscription configurations.
 * @param {string} userID User ID for the configuration.
 * @param {string | null} hostName The hostname from the request.
 * @returns {string} The formatted subscription string.
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
