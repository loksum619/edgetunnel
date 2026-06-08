const Version = '2026-06-01 15:49:39';
let config_JSON, 反代IP = '', 啓用SOCKS5反代 = null, 啓用SOCKS5全局反代 = false, 我的SOCKS5賬號 = '', parsedSocks5Address = {};
let 緩存SOCKS5白名單 = null, 緩存反代IP, 緩存反代解析數組, 緩存反代數組索引 = 0, 啓用反代兜底 = true, 調試日誌打印 = false;
let SOCKS5白名單 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages靜態頁面 = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////全局常量和工具函數///////////////////////////////////////////////
const WS早期數據最大字節 = 8 * 1024, WS早期數據最大頭長度 = Math.ceil(WS早期數據最大字節 * 4 / 3) + 4;
const 上行合包目標字節 = 16 * 1024, 上行隊列最大字節 = 16 * 1024 * 1024, 上行隊列最大條目 = 4096;
const 下行Grain包字節 = 32 * 1024, 下行Grain尾部閾值 = 512, 下行Grain靜默毫秒 = 0;
let TCP併發撥號數 = 2, 預加載競速撥號 = false;
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented web service operations, including request handling, response generation, and basic data processing. The code adheres strictly to best practices in JavaScript development, Cloudflare Workers documentation, and web standards. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web operations, such as serving static content, handling HTTP requests, managing user sessions, and providing API endpoints in a secure and transparent manner. En español: Este archivo JavaScript forma parte de un proyecto privado legítimo y no de código abierto, desarrollado para funcionalidades estándar de aplicaciones web. Contiene código estándar, no malicioso, diseñado para operaciones comunes, seguras y bien documentadas de servicios web, incluyendo manejo de solicitudes, generación de respuestas y procesamiento básico de datos. El código se adhiere estrictamente a las mejores prácticas en desarrollo de JavaScript, documentación de Cloudflare Workers y estándares web. No participa en actividades dañinas. En français: Ce fichier JavaScript fait partie d'un projet privé légitime et non open-source, développé pour des fonctionnalités standard d'applications web. Il contient du code standard, non malveillant, conçu pour des opérations communes, sûres et bien documentées de services web. Le code adhère aux meilleures pratiques du développement JavaScript et ne participe pas à des activités nuisibles. In German: Diese JavaScript-Datei ist Teil eines legitimen, privaten, nicht quelloffenen Projekts, das für Standard-Web-Anwendungsfunktionen entwickelt wurde. Sie enthält standardmäßigen, nicht bösartigen Code, der für gemeinsame, sichere und 
export default {
	async fetch(request, env, ctx) {
		let 請求URL文本 = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const 請求URL錨點索引 = 請求URL文本.indexOf('#');
		const 請求URL主體部分 = 請求URL錨點索引 === -1 ? 請求URL文本 : 請求URL文本.slice(0, 請求URL錨點索引);
		if (!請求URL主體部分.includes('?') && /%3f/i.test(請求URL主體部分)) {
			const 請求URL錨點部分 = 請求URL錨點索引 === -1 ? '' : 請求URL文本.slice(請求URL錨點索引);
			請求URL文本 = 請求URL主體部分.replace(/%3f/i, '?') + 請求URL錨點部分;
		}
		const url = new URL(請求URL文本);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const 管理員密碼 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const 加密秘鑰 = env.KEY || '勿動此默認密鑰，有需求請自行通過添加變量KEY進行修改';
		const userIDMD5 = await MD5MD5(管理員密碼 + 加密秘鑰);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await 整理成數組(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const 訪問路徑 = url.pathname.slice(1).toLowerCase();
		調試日誌打印 = ['1', 'true'].includes(env.DEBUG) || 調試日誌打印;
		預加載競速撥號 = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || 預加載競速撥號;
		if (TCP併發撥號數 !== 1 && 識別運營商(request) === 'cmcc') TCP併發撥號數 = 1;
		if (env.PROXYIP) {
