/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget.local;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.regex.Matcher;

import com.vmware.software_forensic_kit.Java_Gadget_Kit;

public class LocalCalls{
	
	public static String getJarPath() throws URISyntaxException {
		return new File(LocalCalls.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
	}
	public static ArrayList findJars(String filter) {
		Runtime runtime = Runtime.getRuntime();
    	String[] commands = {"find", "/", "-iname", "*.jar"};
    	ArrayList<String> jarList = new ArrayList<String>();
    	String prefixPath = null;
		try {
			prefixPath = getJarPath();
		} catch (URISyntaxException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
 
		try {
			Process proc = runtime.exec(commands);

        	BufferedReader output = new BufferedReader(new 
        	     InputStreamReader(proc.getInputStream()));

        	String s = output.readLine();
        	while (s != null) {
        		if(filter == null || s.contains(filter)) {
        			if(prefixPath != null && s.startsWith(prefixPath) == false) {
	        			System.out.println(s);
	        			jarList.add(s);
        			}
        		}
        	    s = output.readLine();
        	    
        	}
        	output.close();
        	
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return jarList;
		
	}
	public static String jarFileToCallGraphFile(String jar) {
		String sep = System.getProperty("file.separator");
		String outputFile = jar.replaceAll(Matcher.quoteReplacement(File.separator), "_");
		outputFile = outputFile.replaceAll(":", "_");
		outputFile = outputFile.replace(".jar", ".txt");
		return outputFile;
	}
	
	public static ArrayList<String> createCallGraphs(ArrayList<String> jarList , String fileLoc) {
		//java -cp software_forensic_kit.jar gr.gousiosg.javacg.stat.JCallGraph
		String jarPath = "";
		ArrayList<String> outList = new ArrayList<String>();
        String jarName = new java.io.File(LocalCalls.class.getProtectionDomain()
      		  .getCodeSource()
      		  .getLocation()
      		  .getPath())
      		  .getName();

		try {
			jarPath = getJarPath();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String sep = System.getProperty("file.separator");
		
		for (String jar : jarList) {
			
			String outputFile = jarFileToCallGraphFile(jar);
			
			if(new File(jarPath + sep + fileLoc + sep + outputFile).exists() == false) {
				Runtime runtime = Runtime.getRuntime();
		    	String[] commands = {"java", "-cp", jarPath + sep + jarName, "gr.gousiosg.javacg.stat.JCallGraph", "-m", jar};
		    	
		    
				try {
					Process proc = runtime.exec(commands);
					System.out.println(jarPath + sep + fileLoc + sep + outputFile);
		        	BufferedReader output = new BufferedReader(new 
		        	     InputStreamReader(proc.getInputStream()));
		        	BufferedWriter input = new BufferedWriter(new FileWriter(jarPath + sep + fileLoc + sep + outputFile));
		        	outList.add(jarPath + sep + fileLoc + sep + outputFile);
		 
		        	String s = output.readLine();
		        	while (s != null) {
		        		input.write(s);
		        		input.newLine();
		        	    s = output.readLine();
		        	}
		        	
		        	output.close();
		        	input.close();
		        	
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			else {
				outList.add(jarPath + sep + fileLoc + sep + outputFile);
				System.out.println(String.format("Skipping Already Exists: %s", jarPath + sep + fileLoc + sep + outputFile));
			}
			
		}
		return outList;
	}
	
	public static boolean makeDirsNearJar(String dirs) {
		
		try {
			String jarPath = getJarPath();
			String sep = System.getProperty("file.separator");
			return new File(jarPath + sep + dirs).mkdirs();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
}