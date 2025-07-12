// ====================
// Cloudflare Worker: VL over WebSocket + NAT64 + 兜底
// ----------------------------------------------------
//


环境变量 (Vars) 说明：
//   UUID        必填，VL 用户的 UUID                        
//   ID          可选，订阅路径 (默认 12345)                 
//   PROXYIP     可选，反代兜底地址 "ip:sb"     
//   NAT64       可选，是否启用 NAT64 (true|false，默认 true)      
//   隐藏        可选，true|false，true 时订阅接口只返回嘲讽语
//   嘲讽语      可选，自定义隐藏提示语                          

