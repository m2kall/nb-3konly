let 转码 = 'vl', 转码2 = 'ess', 符号 = '://';

// version base on commit 58686d5d125194d34a1137913b3a64ddcf55872f, time is 2024-11-27 09:26:02 UTC.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4'; // <<< IMPORTANT: Replace with your actual UUID

let proxyIP = '';

// 控制订阅页面是否隐藏。
// 设置为 true 则隐藏订阅地址，显示嘲讽语。
// 设置为 false 则显示订阅地址。
// Removed the 'let 隐藏 = false;' here as it will be controlled by env.

// 订阅页面隐藏时显示的嘲讽语
let 嘲讽语 = "哎呀你找到了我，但是我就是不给你看，气不气，嘿嘿嘿";


if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, HIDE_SUBSCRIPTION: string}} env // Added HIDE_SUBSCRIPTION
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			// 从环境变量或默认值获取 userID 和 proxyIP
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;

            // --- IMPORTANT CHANGE HERE ---
            // Read HIDE_SUBSCRIPTION from environment variables.
            // Environment variables are always strings, so we compare to 'true'
            const shouldHideSubscription = env.HIDE_SUBSCRIPTION === 'true';
            // --- END IMPORTANT CHANGE ---

			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case '/':
						// 根路径，显示请求的 Cloudflare 属性
						return new Response(JSON.stringify(request.cf), { status: 200 });
					case `/${userID}`: {
						// 当访问 yourdomain.com/your-uuid 时，根据 'shouldHideSubscription' 变量决定响应
						if (shouldHideSubscription) { // Used the new variable here
							// 如果隐藏为 true，则返回嘲讽语
							return new Response(嘲讽语, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						} else {
							// 如果隐藏为 false，则生成并返回订阅配置
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
						// 其他未匹配的路径返回 404
						return new Response('Not found', { status: 404 });
				}
			} else {
				// 处理 WebSocket 升级请求，用于代理功能
				return await dynamicProtocolOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			// 捕获并返回任何发生的错误
			return new Response(e.toString());
		}
	},
};

/**
 * 处理 WebSocket 请求，建立秘密隧道进行代理。
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function dynamicProtocolOverWSHandler(request) {
	// 创建 WebSocket 配对
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

	// WebSocket -> 远程目标 (数据流向：从 WebSocket 到远程目标)
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

			// 解析协议头部，获取目标地址和端口
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
				// 协议解析出错，抛出错误中断连接
				throw new Error(message); 
			}
			// UDP 代理目前仅支持 DNS (端口 53)
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP proxy only enable for DNS which is port 53'); 
				}
			}
			// 响应头部版本信息
			const dynamicProtocolResponseHeader = new Uint8Array([dynamicProtocolVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				return handleDNSQuery(rawClientData, webSocket, dynamicProtocolResponseHeader, log);
			}
			// 处理 TCP 出站连接
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

	// 返回 WebSocket 响应
	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * 处理出站 TCP 连接。
 * @param {any} remoteSocket
 * @param {number} addressType 远程地址类型。
 * @param {string} addressRemote 远程地址。
 * @param {number} portRemote 远程端口。
 * @param {Uint8Array} rawClientData 原始客户端数据。
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket WebSocket 实例。
 * @param {Uint8Array} dynamicProtocolResponseHeader 动态协议响应头。
 * @param {function} log 日志函数。
 * @returns {Promise<void>}
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
		await writer.write(rawClientData); // 首次写入客户端数据（例如 TLS 握手数据）
		writer.releaseLock();
		return tcpSocket;
	}

	// 如果 CF 的 TCP 连接没有收到数据，就尝试“重定向”IP (可选的代理IP)
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

	// 将远程 Socket 的数据流向 WebSocket
	remoteSocketToWS(tcpSocket, webSocket, dynamicProtocolResponseHeader, retry, log);
}

/**
 * 创建一个可读的 WebSocket 流。
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader 用于 WebSocket 0-RTT 的早期数据头。
 * @param {(info: string)=> void} log 日志函数。
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
 * 处理动态协议头部。
 * @param {ArrayBuffer} dynamicProtocolBuffer 动态协议数据。
 * @param {string} userID 用户ID。
 * @returns {object} 解析结果。
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
	// 校验用户 ID
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
		// TCP
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
 * 将远程 Socket 的数据流向 WebSocket。
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket 远程 Socket 实例。
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket WebSocket 实例。
 * @param {ArrayBuffer} dynamicProtocolResponseHeader 动态协议响应头。
 * @param {(() => Promise<void>) | null} retry 重试函数。
 * @param {*} log 日志函数。
 */
async function remoteSocketToWS(remoteSocket, webSocket, dynamicProtocolResponseHeader, retry, log) {
	let dynamicProtocolHeader = dynamicProtocolResponseHeader;
	let hasIncomingData = false; // 检查远程 Socket 是否有传入数据
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
						// 首次发送带头部信息
						webSocket.send(await new Blob([dynamicProtocolHeader, chunk]).arrayBuffer());
						dynamicProtocolHeader = null;
					} else {
						// 后续直接发送数据
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

	// 如果 CF 连接 socket 没有收到任何数据，就尝试重试（如果重试函数存在）
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

/**
 * 将 Base64 字符串转换为 ArrayBuffer。
 * @param {string} base64Str 
 * @returns {object} 包含早期数据或错误的对象。
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
 * 校验 UUID 格式。
 * @param {string} uuid 
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * 安全关闭 WebSocket 连接。
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
 * 处理 DNS 查询。
 * @param {ArrayBuffer} udpChunk UDP 数据块。
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket WebSocket 实例。
 * @param {ArrayBuffer} dynamicProtocolResponseHeader 动态协议响应头。
 * @param {(string)=> void} log 日志函数。
 */
async function handleDNSQuery(udpChunk, webSocket, dynamicProtocolResponseHeader, log) {
	try {
		const dnsServer = '8.8.4.4'; // 硬编码的 DNS 服务器
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
 * 生成动态协议配置（V2Ray 和 Clash-Meta 订阅）。
 * @param {string} userID 用户ID。
 * @param {string | null} hostName 主机名。
 * @returns {string} 订阅配置字符串。
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
