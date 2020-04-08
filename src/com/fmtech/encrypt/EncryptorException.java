/**
 * 加解密异常类
 *
 * @copyright   Copyright © 2019 枫芒科技
 * @author      wangguanqun <wangguanqun@fmtech.me>
 * @version     1.0.0
 * @link        http://www.fmtech.me
 */

package com.fmtech.encrypt;

@SuppressWarnings("serial")
public class EncryptorException extends Exception
{
    public final static int ERROR_INVALID_SIGNATURE = -10001; // 签名校验错误
    public final static int ERROR_INVALID_COMPANY_KEY = -10002; // 企业标识校验错误
    public final static int ERROR_ENCRYPT_AES = -10003; // 加密失败
    public final static int ERROR_COMPUTER_SIGNATURE = -10004; // 生成签名错误
    public final static int ERROR_DECRYPT_AES = -10005; // 解密失败
    public final static int ERROR_ILLEGAL_BUFFER = -10006; // 解密后得到的buffer非法

    private int code;

    private static String getMessage(int code)
    {
        switch (code) {
            case ERROR_INVALID_SIGNATURE:
                return "签名校验错误";
		case ERROR_INVALID_COMPANY_KEY:
                return "企业标识校验错误";
            case ERROR_ENCRYPT_AES:
                return "AES 校验错误";
            case ERROR_COMPUTER_SIGNATURE:
                return "生成签名错误";
            case ERROR_DECRYPT_AES:
                return "解密失败";
            case ERROR_ILLEGAL_BUFFER:
                return "解密后得到的buffer非法";
            default:
                return null;
        }
    }

    public int getCode()
    {
        return code;
    }

    EncryptorException(int code)
    {
        super(getMessage(code));
        this.code = code;
    }
}
