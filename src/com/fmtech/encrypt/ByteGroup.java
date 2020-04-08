/**
 * 字节数组
 *
 * @copyright   Copyright © 2019 枫芒科技
 * @author      wangguanqun <wangguanqun@fmtech.me>
 * @version     1.0.0
 * @link        http://www.fmtech.me
 */

package com.fmtech.encrypt;

import java.util.ArrayList;

public class ByteGroup
{
	ArrayList<Byte> byteContainer = new ArrayList<Byte>();

	public byte[] toBytes()
	{
		byte[] bytes = new byte[byteContainer.size()];
		for (int i = 0; i < byteContainer.size(); i++) {
			bytes[i] = byteContainer.get(i);
		}
		return bytes;
	}

	public ByteGroup addBytes(byte[] bytes)
	{
		for (byte b : bytes) {
			byteContainer.add(b);
		}
		return this;
	}

	public int size()
	{
		return byteContainer.size();
	}
}
