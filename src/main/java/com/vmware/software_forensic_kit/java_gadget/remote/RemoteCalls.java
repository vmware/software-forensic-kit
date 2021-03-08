/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget.remote;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Vector;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;
import com.jcraft.jsch.ChannelSftp.LsEntry;

public class RemoteCalls{
	
	private static RemoteCalls instance;
	private JSch sshChannel;
	private Session conn;
	private boolean isConnected = false;
	public static RemoteCalls getInstance() {
        if (instance == null) {
             instance = new RemoteCalls();
        }
        return instance;
    }

    private RemoteCalls() {
    	sshChannel = new JSch();
    }
    
    public void connect(String user, String ip, String pass) {
    	try {
    		
			conn = sshChannel.getSession(user, ip, 22);
			conn.setPassword(pass);
			java.util.Properties config = new java.util.Properties(); 
    		config.put("StrictHostKeyChecking", "no");
    		conn.setConfig(config);
			conn.connect();
			isConnected = true;
		} catch (JSchException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    private void transferFiles(String srcPath, String dstPath, ChannelSftp channel) throws SftpException, FileNotFoundException {
    	File[] files;
    	File newFile = new File(srcPath);
    	
    	if(newFile.isDirectory()) {
    		files = newFile.listFiles();
    	}
    	else {
    		files = new File[] {newFile};
    	}
    	
    	for (File file : files) {
            if (file.isDirectory()) {     
                transferFiles(file.getAbsolutePath(), dstPath, channel); 
            } else {
                System.out.println("File: " + file.getName());
                channel.cd(dstPath);
                channel.put(new FileInputStream(file), file.getName());
            }
        }
    }
    
    private void folderCopy(String srcPath, String dstPath, ChannelSftp channel) throws SftpException, FileNotFoundException {
    	String sep = System.getProperty("file.separator");
		
    	Vector<ChannelSftp.LsEntry> srcList = channel.ls(srcPath);
    	for (LsEntry srcItem : srcList) {
    		String srcFN = srcItem.getFilename();
    		
    		if(srcItem.getAttrs().isDir() == false) {
    			new File(dstPath + sep + srcFN);
    			channel.get(srcPath + "/" + srcFN, dstPath + sep + srcFN);
    		}
    		else if(".".equals(srcFN) == false && "..".equals(srcFN) == false ) {
    			new File(dstPath + sep + srcFN).mkdirs();
    			folderCopy(srcPath + sep + srcFN, dstPath + sep + srcFN, channel );
    		}
    	}
    	
    }
    public void getFiles(String srcPath, String dstPath) {
    	if(isConnected == false) {
			System.out.println("Not connected connect first");
		    System.exit(0);
		}
		try {
			ChannelSftp channel = (ChannelSftp)conn.openChannel("sftp");
		
	        channel.connect();
	        new File(dstPath).mkdirs();
	        channel.lcd(dstPath);
	        folderCopy(srcPath, dstPath, channel);
	        channel.exit();
	        channel.disconnect();
	        
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
      
    }
    public void sendFiles(String srcPath, String dstPath) {
    	if(isConnected == false) {
			System.out.println("Not connected connect first");
		    System.exit(0);
		}
		try {
			ChannelSftp channel = (ChannelSftp)conn.openChannel("sftp");
		
	        channel.connect();
	        transferFiles(srcPath, dstPath, channel);
	        channel.exit();
	        channel.disconnect();
	        
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
      
    }
	public String sendCommand(String cmd) {
		if(isConnected == false) {
			System.out.println("Not connected connect first");
		    System.exit(0);
		}
		StringBuilder outputBuffer = new StringBuilder();

	     try {
	        Channel channel = conn.openChannel("exec");
	        ((ChannelExec)channel).setCommand(cmd);
	        
	        InputStream out = channel.getInputStream();
	        channel.connect();
	        
	        int readByte = out.read();
	        while(readByte != 0xffffffff) {
	           outputBuffer.append((char)readByte);
	           readByte = out.read();
	        }

	        channel.disconnect();
	        String outBuf = outputBuffer.toString();
	        out.close();
	        return outBuf;
	        
	     }
	     catch(Exception e) {
	       System.out.println(e.getMessage());
	       System.exit(0);
	     }
	     
	     return "";
	     
	}
	
	
}