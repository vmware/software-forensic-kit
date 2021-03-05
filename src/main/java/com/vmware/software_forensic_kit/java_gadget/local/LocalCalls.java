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
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.stream.Stream;

public class LocalCalls{
	
	public static List<String> outputList = Collections.synchronizedList(new ArrayList<String>());
	public static String OS = System.getProperty("os.name");
	public static int createdJarNumber = 0;
	public static String getJarPath() {
		try {
			return new File(LocalCalls.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			return "";
		}
	
	}
	public static Stream<Path> walkPath(Path path){
		if(Files.isReadable(path) == false)
			return Stream.of(path);
       
    	if(Files.isDirectory(path) == false)
    		return Stream.of(path);
        try{
            return Stream.concat(Stream.of(path), Files.list(path));
        } 
        catch (IOException ioe){
            return Stream.of(path);
        }
        
    }
	public static ArrayList findJars(String filter) {
		return _findJars(filter, false);
	}
	public static ArrayList _findJars(String filter, boolean printToConsole) {
		Runtime runtime = Runtime.getRuntime();
		
		String linuxDirectory = "/";
		String windowsDirectory = "C:\\";
		
		String directory = linuxDirectory;
		if(LocalCalls.OS.startsWith("Windows")) 
			directory = windowsDirectory;
    	
    	ArrayList<String> jarList = new ArrayList<String>();
    	String prefixPath = getJarPath();
 
		// Process proc = windowsbuilder.start();
    	//DEBUG REMOVE
    	Stream<Path> mapped;
    	LocalFileVisitor visit = new LocalFileVisitor(printToConsole, ".jar", filter);
		try {
			
			Files.walkFileTree(Paths.get(directory), visit);
			
			return visit.jarList();
			//mapped = Files.walk(Paths.get(directory))
			//.flatMap(LocalCalls::walkPath)
			
			//mapped = Files.walkFileTree(Paths.get(directory), visit)
			//.filter(x -> x.toString().endsWith(".jar"))
			//.filter(x -> x.toString().contains(filter));
			//mapped.forEach(x -> {jarList.add(x.toString()); if(printToConsole)System.out.println(String.format("Jar_Found:[%s]", x)); });
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//.filter(Files::isRegularFile)
		return null;
		
	}
	public static ArrayList<String> _runCommand(String[] commands) {
		Runtime runTime = Runtime.getRuntime();
		ArrayList<String> results = new ArrayList<String>();
		
		try {
			
			Process pid = runTime.exec(commands);
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(pid.getInputStream()));
			BufferedReader stdError = new BufferedReader(new InputStreamReader(pid.getErrorStream()));
			String s = null;
			
			while ((s = stdInput.readLine()) != null) { results.add(s); }
			while ((s = stdError.readLine()) != null) { System.out.println(s); }
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return results;

	

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
		final String  jarPath = getJarPath();
		ArrayList<String> outList = new ArrayList<String>();
        String jarName = new java.io.File(LocalCalls.class.getProtectionDomain()
      		  .getCodeSource()
      		  .getLocation()
      		  .getPath())
      		  .getName();

		
		String sep = System.getProperty("file.separator");
		ExecutorService executorService = Executors.newFixedThreadPool(20);

		PrintStream console = System.out;
		ArrayList<String> options = new ArrayList<String>();
		options.add("-m");
		int total = jarList.size();
		createdJarNumber = 0;
		try {
			for (String jar : jarList) {
			
				executorService.execute(() -> {
					String outputFile = LocalCalls.jarFileToCallGraphFile(jar);
					
					if(new File(jarPath + sep + fileLoc + sep + outputFile).exists() == false) {
						Runtime runtime = Runtime.getRuntime();
				    	String[] commands = {"java", "-cp", jarPath + sep + jarName, "gr.gousiosg.javacg.stat.JCallGraph", "-m", jar};
				    
						try {
	
							Process proc = runtime.exec(commands);
				        	BufferedReader output = new BufferedReader(new 
				        	     InputStreamReader(proc.getInputStream()));
				        	BufferedWriter input = new BufferedWriter(new FileWriter(jarPath + sep + fileLoc + sep + outputFile));
				        	outputList.add(jarPath + sep + fileLoc + sep + outputFile);
				 
				        	String s = output.readLine();
				        	while (s != null) {
				        		input.write(s);
				        		input.newLine();
				        	    s = output.readLine();
				        	}
				        	createdJarNumber += 1;
				        	System.out.println(String.format("%d of %d", createdJarNumber, total));
				        	output.close();
				        	input.close();
				        	
						} catch (IOException e) {
							// TODO Auto-generated catch block
							System.out.println("Error?");
							System.out.println(e);
							e.printStackTrace();
						}
					}
					else {
						outputList.add(jarPath + sep + fileLoc + sep + outputFile);
					}
		        });
				
			}
		}
		finally {
			executorService.shutdown();
		}
        try {
			executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

		return new ArrayList<String>(outputList);
	}
	
	public static boolean makeDirsNearJar(String dirs) {

		String jarPath = getJarPath();
		String sep = System.getProperty("file.separator");
		return new File(jarPath + sep + dirs).mkdirs();
		
	}
	
}
>>>>>>> upstream/master
