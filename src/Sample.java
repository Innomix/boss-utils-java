﻿/**
 * 数据通信加解密示例
 *
 * @copyright   Copyright © 2019 枫芒科技
 * @author      wangguanqun <wangguanqun@fmtech.me>
 * @version     1.0.0
 * @link        http://www.fmtech.me
 */

import com.fmtech.encrypt.EncryptorLogic;
import com.fmtech.encrypt.ResponseData;

public class Sample
{
    public static void main(String[] args) throws Exception
    {
        // 假设企业在BOSS系统上的数据回调配置参数如下
        String companyKey = "b9ca9a10-7878-11ea-ae73-00163e0a522b";
//        String url = "https://api.corp.com";
        String token = "3ELgc0TvWB5X9bXqueBpE4sF2dJvX0";
        String encodingAesKey = "cLU2SZiQtNTckwBYEbpgIj8bvj7Wjs6hY90DoFtNiBH";

		EncryptorLogic encryptor = new EncryptorLogic(companyKey, token, encodingAesKey);

		/*
		|--------------------------------------------------------------------------
		| 示例一：验证回调URL
		|--------------------------------------------------------------------------
		|
		| 企业在 BOSS 系统设置数据回调配置，点击保存时，BOSS系统会向数据回调 URL 发送一个 GET 请求，验证地址有效性
		| GET https://api.corp.com?msgSignature=22e8f41a047f7c9ca30bc6ec1caaf2b3bb354f01&timestamp=1586337853&nonce=24803847&encrypt=5cOIsn%2BKgks5S1%2Flu8Xcn4jn5PpNio00hf2VVpbhaniz5Ip8nuUc2yt3agPiNhRTbp%2FZ2bKuS0ujTyMPMATNWGiQHiwWyKy2ZHv%2BlQ1pcmEGOfnAau78SFdOzQ55rC6D
		|
		| 企业接收到请求后
		| 1、解析出 GET 请求的参数，包括消息体签名(msgSignature)，时间戳(timestamp)，随机数(nonce)以及 BOSS 系统推送过来的加密字符串(encrypt),
		|   这一步注意作URL解码。
		| 2、验证消息体签名的正确性
		| 3、解密出 encrypt 原文，将原文当作 GET 请求的 response，返回给 BOSS 系统
		| 验证签名及解密，可以用 BOSS 系统提供的库函数 decrypt 实现
		|
		*/

		// GET 请求的参数：
		// String msgSignature = HttpUtils.ParseUrl("msgSignature");
		String verifyMsgSign = "22e8f41a047f7c9ca30bc6ec1caaf2b3bb354f01";

		// String timestamp = HttpUtils.ParseUrl("timestamp");
		String verifyTimestamp = "1586337853";

		// String nonce = HttpUtils.ParseUrl("nonce");
		String verifyNonce = "24803847";

		// String encrypt = HttpUtils.ParseUrl("encrypt");
		String verifyEncrypt = "5cOIsn+Kgks5S1/lu8Xcn4jn5PpNio00hf2VVpbhaniz5Ip8nuUc2yt3agPiNhRTbp/Z2bKuS0ujTyMPMATNWGiQHiwWyKy2ZHv+lQ1pcmEGOfnAau78SFdOzQ55rC6D";

        // 需要返回的明文
		String echoStr;
		try {
			echoStr = encryptor.decrypt(verifyEncrypt, verifyMsgSign, verifyNonce, verifyTimestamp);
			System.out.println("VerifyURL, echoStr: " + echoStr);

			// 验证URL成功，将 echoStr 返回
			// HttpUtils.SetResponse(echoStr);
		} catch (Exception e) {
			//验证URL失败，错误原因请查看异常
			e.printStackTrace();
		}

		/*
		|--------------------------------------------------------------------------
		| 示例二：解密 BOSS 系统推送的 POST 消息
		|--------------------------------------------------------------------------
		|
		| 企业在 BOSS 系统成功设置数据回调后，在设备空间状态变更、设备在线状态变更、设备电池电量变更等情况下，BOSS系统会向数据回调 URL 发送一个 POST 请求，
		| 推送变更消息，推送的变更消息经过 BOSS 系统加密，密文格式请参考官方文档
		| POST https://api.corp.com
		|
		| {
		|   "msgSignature": "e349f09f7a9678b27b853afb3e70175738bb5bbb",
		|   "timestamp": 1586338346,
		|   "nonce": 484615793,
		|   "encrypt": "B1QdxkhQCfkrxMnnyou2+DICf1ROTDegA+J3fX+HT0g0Y/l1QN9v4F2RjORvgZ2S6z1eOjJVc/oAdJdLBtMJdSpH4d2mrS0FNu5Tdd/uuRKC1jeLiRw5WsEb4VxezwUAbRZLew5eIjdLzuMeG71FXQxyYPYz/HgolNttExFfdfJEB129Lfj2d8E6EU3ZQMREa04Km69nPGHEhHgIdlYBKBCa3x4HVJm5iHki8AW0S6EtLU59sd9HnzjB2QDSK0BlyuugM9m+eIdqs8MXr7oDQLz7fSjqUzbsWUEbY5sMC8Mvlfp8MvmeC0IDkfJLjbauKph69hALULN9TjaQ3MGW1/kPnf1uXbeOpVl4xgF1ajjWVdsCULrGasGcJsrcrHRrnm7qyXtiWzMEaemogFnzTKTfaplQAREfr9Aegca95nZCjcSRgt1L84juy2jpfADe9578QwonOzUgMENmQn4NLg==",
		| }
		|
		| 企业接收到请求后
		| 1、解析出 POST 请求的参数，包括消息体签名(msgSignature)，时间戳(timestamp)，随机数(nonce)以及 BOSS 系统推送过来的随机加密字符串(encrypt)
		| 2、验证消息体签名的正确性
		| 3、解密出 encrypt 原文，解密出来的明文是一个 json 字符串，需要转换成 json 对象，明文格式请参考官方文档
		| 验证签名及解密，可以用 BOSS 系统提供的库函数 decrypt 实现
		|
		*/

        // POST 请求的参数
		String reqMsgSign = "e349f09f7a9678b27b853afb3e70175738bb5bbb";
		String reqTimestamp = "1586338346";
		String reqNonce = "484615793";
		String reqEncrypt = "B1QdxkhQCfkrxMnnyou2+DICf1ROTDegA+J3fX+HT0g0Y/l1QN9v4F2RjORvgZ2S6z1eOjJVc/oAdJdLBtMJdSpH4d2mrS0FNu5Tdd/uuRKC1jeLiRw5WsEb4VxezwUAbRZLew5eIjdLzuMeG71FXQxyYPYz/HgolNttExFfdfJEB129Lfj2d8E6EU3ZQMREa04Km69nPGHEhHgIdlYBKBCa3x4HVJm5iHki8AW0S6EtLU59sd9HnzjB2QDSK0BlyuugM9m+eIdqs8MXr7oDQLz7fSjqUzbsWUEbY5sMC8Mvlfp8MvmeC0IDkfJLjbauKph69hALULN9TjaQ3MGW1/kPnf1uXbeOpVl4xgF1ajjWVdsCULrGasGcJsrcrHRrnm7qyXtiWzMEaemogFnzTKTfaplQAREfr9Aegca95nZCjcSRgt1L84juy2jpfADe9578QwonOzUgMENmQn4NLg==";

		try {
			String jsonStr = encryptor.decrypt(reqEncrypt, reqMsgSign, reqNonce, reqTimestamp);
			System.out.println("Decrypt, jsonStr: " + jsonStr);

			// 将明文 Json 字符串转为 Json 对象
		} catch (Exception e) {
			// 解密失败，失败原因请查看异常
			e.printStackTrace();
		}
		
        /*
        |--------------------------------------------------------------------------
        | 示例三：加密消息
        |--------------------------------------------------------------------------
        |
        | 企业如果需要向 BOSS 系统 POST 加密消息，按如下方法组装数据
        | 假如推送的数据明文如下（json字符串）
        |
        | {
        |   "msgType": "change_space_status",
        |   "data": {
        |      "deviceName": "d896e0ff10023d5c",
        |      "applicationKey": "meeting",
        |      "companyKey": "b9ca9a10-7878-11ea-ae73-00163e0a522b",
        |      "spaceId": 1,
        |      "spaceStatus": 1,
        |      "purpose": "DETECTOR",
        |      "lastReportTime": "2020-03-30 12:30:01",
        |    },
        |   "createTime": 1585542601
        | }
        |
        | 1、将json字符串明文、企业标识CompanyKey加密得到密文
        | 2、生成时间戳(timestamp)、随机数(nonce)，使用加密 token、步骤1得到的密文，生成消息体签名
        | 3、将密文，消息体签名、时间戳、随机数拼接成 json 格式的字符串，POST 给 BOSS系统
        | 加密过程可以用 BOSS 系统提供的库函数 encrypt 实现
        |
        */
		String sendJsonStr = "{\"msgType\":\"change_space_status\",\"data\":{\"deviceName\": \"d896e0ff10023d5c\",\"applicationKey\": \"meeting\",\"companyKey\": \"b9ca9a10-7878-11ea-ae73-00163e0a522b\",\"spaceId\": 1,\"spaceStatus\": 1,\"purpose\": \"DETECTOR\",\"lastReportTime\": \"2020-03-30 12:30:01\"},\"createTime\": 1585542601}";
		try {
			ResponseData response = encryptor.encrypt(sendJsonStr);
			System.out.println("Encrypt, sendObj encrypt: " + response.getEncrypt());
			System.out.println("Encrypt, sendObj msgSignature: " + response.getMsgSignature());
			System.out.println("Encrypt, sendObj timestamp: " + response.getTimestamp());
			System.out.println("Encrypt, sendObj nonce: " + response.getNonce());
		} catch (Exception e) {
		    // 加密失败，失败原因请查看异常
			e.printStackTrace();
		}
	}
}
