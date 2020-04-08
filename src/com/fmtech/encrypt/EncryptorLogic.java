/**
 * 数据通信加解密工具类
 *
 * @copyright   Copyright © 2019 枫芒科技
 * @author      wangguanqun <wangguanqun@fmtech.me>
 * @version     1.0.0
 * @link        http://www.fmtech.me
 */

package com.fmtech.encrypt;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// 需要导入jar包 commons-codec-1.9（或commons-codec-1.8等其他版本）
// 官方下载地址：http://commons.apache.org/proper/commons-codec/download_codec.cgi
import org.apache.commons.codec.binary.Base64;

public class EncryptorLogic
{
    /*
    |--------------------------------------------------------------------------
    | Encryptor Logic
    |--------------------------------------------------------------------------
    |
    | 数据通信加解密工具的业务逻辑，包含加密encrypt、解密decrypt(UTF8编码的字符串)
    |
    | 异常java.security.InvalidKeyException:illegal Key Size的解决方案
    | 在官方网站下载JCE无限制权限策略文件，JDK7的下载地址：
    | http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
    | 下载后解压，可以看到local_policy.jar和US_export_policy.jar以及readme.txt
    | 如果安装了JRE，将两个jar文件放到%JRE_HOME%\lib\security目录下覆盖原来的文件
    | 如果安装了JDK，将两个jar文件放到%JDK_HOME%\jre\lib\security目录下覆盖原来文件
    |
    */

    /**
    * 企业标识.
    */
    protected String companyKey;

    /**
     * 用于计算签名的 token
    */
    protected String token;

    /**
     * 未被base64编码的 aesKey
     */
    protected byte[] aesKey;

    /**
    * base64编码、解码对象
    */
    protected Base64 base64 = new Base64();

    /**
    * 块大小（字节）
    */
    protected int blockSize = 32;

    /**
    * 字符编码对象
    */
    protected static Charset CHARSET = Charset.forName("utf-8");

    /**
     * 构造方法
     *
     * @param String companyKey 企业标识
     * @param String token 用于计算签名的 token
     * @param String encodingAESKey 经过 base64 编码的 AESKey
     */
    public EncryptorLogic(String companyKey, String token, String encodingAESKey)
    {
        this.companyKey = companyKey;
        this.token = token;
        aesKey = Base64.decodeBase64(encodingAESKey + "=");
    }

    /**
     * 加密需要发送的消息
     *
     * @param String msg 待加密的明文消息
     * @return ResponseData response 响应对象（包含加密字符串、签名、时间戳、随机数）
     * @throws EncryptorException
     */
    public ResponseData encrypt(String msg) throws EncryptorException
    {
        // 明文字符串由16个字节的随机字符串、4个字节的 msg 长度、明文 msg 和 companyKey 拼接组成。
        // 其中 msg 长度为 msg 的字节数，网络字节序；companyKey 为企业标识；
        ByteGroup byteCollector = new ByteGroup();
        String randomStr = getRandomStr(16);
        byte[] randomStrBytes = randomStr.getBytes(CHARSET);
        byte[] msgBytes = msg.getBytes(CHARSET);
        byte[] networkBytesOrder = getNetworkBytesOrder(msgBytes.length);
        byte[] companyKeyBytes = companyKey.getBytes(CHARSET);

        byteCollector.addBytes(randomStrBytes);
		byteCollector.addBytes(networkBytesOrder);
		byteCollector.addBytes(msgBytes);
		byteCollector.addBytes(companyKeyBytes);

        // 将拼接的字符串采用 PKCS#7 填充，长度扩充至32字节的倍数
		byte[] padBytes = pkcs7Pad(byteCollector.size());
		byteCollector.addBytes(padBytes);

		// 获得最终的字节流, 未加密
		byte[] unencrypted = byteCollector.toBytes();

		String base64Encrypted;
        try {
            // 使用 AES-256-CBC 密码学方式加密字符串，然后使用 base64 编码
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(aesKey, 0, 16);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

            // 加密
            byte[] encrypted = cipher.doFinal(unencrypted);

            // 使用BASE64对加密后的字符串进行编码
            base64Encrypted = base64.encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            throw new EncryptorException(EncryptorException.ERROR_ENCRYPT_AES);
        }

        String nonce = Integer.toString(getRandomInt(10000000, 999999999));
        String timestamp = Long.toString(System.currentTimeMillis()/1000);

        ResponseData response = new ResponseData();
        response.setEncrypt(base64Encrypted);
        response.setMsgSignature(signature(token, timestamp, nonce, base64Encrypted));
        response.setTimestamp(timestamp);
        response.setNonce(nonce);
        return response;
    }

    /**
     * 解密收到的消息
     *
     * @param String content 已加密的内容
     * @param String msgSignature 签名
     * @param String nonce 随机数
     * @param String timestamp 时间戳
     * @return String 解密后的明文，如果是 get 请求验证地址，是一个普通字符串；如果是post请求，是一个json字符串
     * @throws EncryptorException
     */
    public String decrypt(String content, String msgSignature, String nonce, String timestamp) throws EncryptorException
    {
        // 生成签名并验证
        String sign = signature(token, timestamp, nonce, content);
        if (!sign.equals(msgSignature)) {
            throw new EncryptorException(EncryptorException.ERROR_INVALID_SIGNATURE);
        }

        byte[] original;

        try {
			// 设置解密模式为AES的CBC模式
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec key_spec = new SecretKeySpec(aesKey, "AES");
			IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
			cipher.init(Cipher.DECRYPT_MODE, key_spec, iv);

			// 使用BASE64对密文进行解码
			byte[] encrypted = Base64.decodeBase64(content);

			// 解密
			original = cipher.doFinal(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			throw new EncryptorException(EncryptorException.ERROR_DECRYPT_AES);
		}

        String msg, fromCompanyKey;
        try {
			// 去除补位字符
			byte[] bytes = pkcs7Unpad(original);
			
			// 分离16位随机字符串,网络字节序和 companyKey
			byte[] networkOrder = Arrays.copyOfRange(bytes, 16, 20);

			int msgLength = recoverNetworkBytesOrder(networkOrder);
			
			msg = new String(Arrays.copyOfRange(bytes, 20, 20 + msgLength), CHARSET);
			fromCompanyKey = new String(Arrays.copyOfRange(bytes, 20 + msgLength, bytes.length), CHARSET);
		} catch (Exception e) {
			e.printStackTrace();
			throw new EncryptorException(EncryptorException.ERROR_ILLEGAL_BUFFER);
		}

		// companyKey 不相同
		if (!fromCompanyKey.equals(companyKey)) {
			throw new EncryptorException(EncryptorException.ERROR_INVALID_COMPANY_KEY);
		}
		return msg;
    }

    /**
     * 将整数转为4个字节的网络字节序二进制
     *
     * @param int sourceNumber 需要转换的整数
     * @return byte[]
     */
	public byte[] getNetworkBytesOrder(int sourceNumber)
	{
		byte[] orderBytes = new byte[4];
		orderBytes[3] = (byte) (sourceNumber & 0xFF);
		orderBytes[2] = (byte) (sourceNumber >> 8 & 0xFF);
		orderBytes[1] = (byte) (sourceNumber >> 16 & 0xFF);
		orderBytes[0] = (byte) (sourceNumber >> 24 & 0xFF);
		return orderBytes;
	}

	/**
     * 将4个字节的网络字节序二进制转为整数
     *
     * @param byte[] orderBytes 网络字节序二进制
     * @return int
     */
	public int recoverNetworkBytesOrder(byte[] orderBytes)
	{
		int sourceNumber = 0;
		for (int i = 0; i < 4; i++) {
			sourceNumber <<= 8;
			sourceNumber |= orderBytes[i] & 0xff;
		}
		return sourceNumber;
	}

    /**
     * 返回指定长度的随机字符串，只包含大小字母和数字
     *
     * @param int len 需要返回的字符串长度
     * @return String
     */
    public String getRandomStr(int len)
    {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < len; i++) {
            int number = random.nextInt(chars.length());
            sb.append(chars.charAt(number));
        }
        return sb.toString();
    }

    /**
     * 返回指定范围内的随机数
     *
     * @param int min 最小值
     * @param int max 最大值
     * @return int
     */
    public int getRandomInt(int min, int max)
    {
        return new Random().nextInt(max)%(max - min + 1) + min;
    }

    /**
     * 将接收到的参数按字典序排序，拼接后，使用 SHA1 加密，生成签名
     *
     * @param String token 签名密钥
     * @param String timestamp 时间戳
     * @param String nonce 随机数
     * @param String encrypt 加密字符串
     * @return String 签名
     * @throws EncryptorException
     */
    public String signature(String token, String timestamp, String nonce, String encrypt) throws EncryptorException
    {
        try {
            String[] array = new String[] { token, timestamp, nonce, encrypt };
            StringBuffer sb = new StringBuffer();

            // 字符串排序
            Arrays.sort(array);
            for (int i = 0; i < 4; i++) {
                sb.append(array[i]);
            }
            String str = sb.toString();

            // SHA1签名生成
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(str.getBytes());
            byte[] digest = md.digest();

            StringBuffer hexstr = new StringBuffer();
            String shaHex = "";
            for (int i = 0; i < digest.length; i++) {
                shaHex = Integer.toHexString(digest[i] & 0xFF);
                if (shaHex.length() < 2) {
                    hexstr.append(0);
                }
                hexstr.append(shaHex);
            }
            return hexstr.toString();
        } catch (Exception e) {
            e.printStackTrace();
            throw new EncryptorException(EncryptorException.ERROR_COMPUTER_SIGNATURE);
        }
    }

    /**
     * 将字符串使用 PKCS#7 pad 方法填充，使长度至32字节的倍数
     *
     * @param int count 需要填充的长度
     * @return byte[] 用于填充的字节数组
     */
    public byte[] pkcs7Pad(int count)
    {
        // 计算需要填充的位数
        int padSize = blockSize - (count % blockSize);
        if (padSize == 0) {
            padSize = blockSize;
        }

        // 获得填充所用的字符
        char padChar = chr(padSize);
        String tmp = new String();
        for (int i = 0; i < padSize; i++) {
            tmp += padChar;
        }
        return tmp.getBytes(CHARSET);
    }

	/**
	 * 将数字转化成ASCII码对应的字符，用于对明文进行填充
	 *
	 * @param int num 需要转化的数字
	 * @return char 转化得到的字符
	 */
	public char chr(int num)
	{
		byte target = (byte) (num & 0xFF);
		return (char) target;
	}

    /**
     * 使用 PKCS#7 unpad 方法将多余的字符去掉
     *
     * @param byte[] text 待截取的已被填充的内容
     * @return byte[] 截取后的字节数组
     */
    public byte[] pkcs7Unpad(byte[] text)
    {
        int pad = (int) text[text.length - 1];
        if (pad < 1 || pad > blockSize) {
            pad = 0;
        }
        return Arrays.copyOfRange(text, 0, text.length - pad);
    }
}
