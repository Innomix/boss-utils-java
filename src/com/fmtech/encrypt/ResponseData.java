/**
 * 响应的数据结构
 *
 * @copyright   Copyright © 2019 枫芒科技
 * @author      wangguanqun <wangguanqun@fmtech.me>
 * @version     1.0.0
 * @link        http://www.fmtech.me
 */

package com.fmtech.encrypt;


public class ResponseData
{
	public String encrypt;
	public String msgSignature;
	public String timestamp;
	public String nonce;
	
	public String getEncrypt() {
		return encrypt;
	}
	
	public void setEncrypt(String encrypt) {
		this.encrypt = encrypt;
	}
	
	public String getMsgSignature() {
		return msgSignature;
	}
	
	public void setMsgSignature(String msgSignature) {
		this.msgSignature = msgSignature;
	}
	
	public String getTimestamp() {
		return timestamp;
	}
	
	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}
	public String getNonce() {
		return nonce;
	}
	
	public void setNonce(String nonce) {
		this.nonce = nonce;
	}
}
