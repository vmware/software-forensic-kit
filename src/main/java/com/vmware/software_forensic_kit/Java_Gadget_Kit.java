/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit;

import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;

import com.vmware.software_forensic_kit.java_gadget.Java_Gadget;
import com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Dynamic;
import com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Injector;
import com.vmware.software_forensic_kit.java_gadget.local.LocalCalls;
import com.vmware.software_forensic_kit.java_gadget.remote.RemoteCalls;

public class Java_Gadget_Kit {
	public static boolean exitprocess = false;
	public static void printUsage(HelpFormatter formatter, Options options) {
		String footer = "Example Usage:\r\n" + 
        		"	>java -jar software_forensic_kit.jar -u root -d 10.160.157.187 -p test123 -s \"ExampleClass:functionA\" -f /var/www -hm -rp my.class.path.\r\n" + 
        		"	Or using wildcards * for filter\r\n" + 
        		"	>java -jar software_forensic_kit.jar -u root -d 10.160.157.187 -p test123 -s \"ExampleClass*functionA\" -f /var/www -pp -rp my.class.path. -o C:\\test\\output\r\n\n" +
        		"   If you want to run software forensic kit locally simply exclude (user, domain and password variables)\r\n\n" +
        		"   >java -jar software_forensic_kit.jar -s \"ExampleClass:functionA\" -f C:\\test -pp \r\n\n" +
        		"For Interactive Mode:\r\n" +
        		"   >java -jar software_forensic_kit.jar -I";
        formatter.setOptionComparator(null);
        formatter.printHelp("Software_Forensic_Kit", "", options, footer, true);

        System.exit(1);
	}
	
    public static void main(String[] args) {
    	
    	CommandLine cmd = generateCMD(args);
        
        
        if(cmd.hasOption("I")) {
        	interactiveMode(cmd);
        }
        	
        String user = cmd.getOptionValue("username");
        String pass = cmd.getOptionValue("password");
        String ip = cmd.getOptionValue("domain");
        
        File jar = new java.io.File(Java_Gadget_Kit.class.getProtectionDomain()
        		  .getCodeSource()
        		  .getLocation()
        		  .getPath());
        		//.getName();
        String jarName = jar.getName();
        
        System.out.println("Jar Location: " + jar.toString());
        if(user != null && pass != null && ip != null) {
        	//remote call here
        	String outFolder = cmd.getOptionValue("output");
        	RemoteCalls rc = RemoteCalls.getInstance();
        	rc.connect(user,  ip,  pass);
        	rc.sendCommand("rm -rf /var/kit/files/output");
        	rc.sendCommand("mkdir -p /var/kit/files/output");
        	String jarpath = "unknown.jar";
        	try {
				jarpath = new File(Java_Gadget_Kit.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
			} catch (URISyntaxException e1) {

				// TODO Auto-generated catch block
				e1.printStackTrace();
				System.exit(3);
			}
        	rc.sendFiles(jarpath, "/var/kit");

        	
        	Option[] opts = cmd.getOptions();
        	String newLocalCmd = "";
        	for (Option opt : opts) {
        		String optStr = opt.getOpt();
        		if(optStr != "u" && optStr != "p" && optStr != "d") {
        			if(opt.getValue() != null && opt.getValues().length > 0 && opt.hasArg())
        				newLocalCmd += "-" + optStr + " " + String.join(" ", opt.getValues()) + " ";
        			else
        				newLocalCmd += "-" + optStr + " ";
        		}
        	}
        	newLocalCmd = String.format("java -jar /var/kit/%s %s", jarName, newLocalCmd);
        	System.out.println(newLocalCmd);
        	String output = rc.sendCommand(newLocalCmd);
        	boolean getRemoteOutput = false;
        	if(cmd.hasOption("-gm") || cmd.hasOption("-pp") || cmd.hasOption("-g")) {
        		getRemoteOutput = true;
        	}

        	String sep = System.getProperty("file.separator");
        	
        	String outDir = "output_%d_%d_%d";
        	Calendar c = Calendar.getInstance();
        	int hour = c.get(Calendar.HOUR_OF_DAY);
        	int minute = c.get(Calendar.MINUTE);
        	int second = c.get(Calendar.SECOND);
        	outDir = LocalCalls.getJarPath() + sep + String.format(outDir,  hour, minute, second);
			
        	
        	if(cmd.hasOption("output")) {
        		outDir = cmd.getOptionValue("output");
        	}
        	rc.getFiles("/var/kit/files/output", outDir);
        	
        	if(getRemoteOutput == true) {
        	     try {
        	    	outDir = outDir + sep + String.format("output_%d_%d_%d",  hour, minute, second) + ".txt";
        	    	BufferedWriter outFile = new BufferedWriter(new FileWriter(outDir));              	   
					outFile.write(output);
					outFile.close();
					
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					System.out.println(output);
					
				}
        	   
        	}
        	System.out.println(String.format("Files copied to: %s", outDir));
        	
        }
        else {
        	//Local call
        	/*
        	 * Takes too long
        	 * WildcardFileFilter fileFilter = new WildcardFileFilter("*.jar");
        	WildcardFileFilter dirFilter = new WildcardFileFilter("*");
        	//local execute find all jars
        	File dir = new File("/");
    		
    		List<File> files = (List<File>) FileUtils.listFiles(dir, fileFilter, dirFilter);
    		for (File file : files) {
    			System.out.println("file: " + file.getAbsolutePath());
    		}*/
        	mainLocalCall(Java_Gadget.createOptions(), cmd);
        	
        	
        }
        
        System.out.println("Finished!");
        System.exit(0);
        

    }
    public static void mainLocalCall(Options javaGadgetOptions, CommandLine cmd) {
    	
    	String filter = cmd.getOptionValue("filter");
    	String sep = System.getProperty("file.separator");
    	String localOutput = "files" + sep + "output";
    	String localCG = "files" + sep + "callgraph";
    	
    	
    	ArrayList<String> jarList = LocalCalls._findJars(filter, cmd.hasOption("verbose"));
    	LocalCalls.makeDirsNearJar(localOutput);
    	LocalCalls.makeDirsNearJar(localCG);
    	
    	ArrayList<String> callGraphList = LocalCalls.createCallGraphs(jarList, localCG);
   
    	HashMap<String, String> map = new HashMap<String, String>();
        for (Option opt : cmd.getOptions()) {
        	if(javaGadgetOptions.hasOption(opt.getOpt()))
        		map.put(opt.getLongOpt(), cmd.getOptionValue(opt.getOpt()));
        }
        boolean verbose = cmd.hasOption("verbose");
        callGraphList.forEach(x -> {if(verbose)System.out.println(String.format("Callgraph_Created:[%s] ", x));});
        System.out.println("Callgraph_Out:{");
        callGraphList.forEach(x -> {Java_Gadget.executeRequestUsingCGFile(map, x);});
        System.out.println("}:Callgraph_Out_End");
    	
    	if(cmd.hasOption("output")) {
    		String destDir = cmd.getOptionValue("output");		
    		String outDir = LocalCalls.getJarPath() + sep + "files" + sep + "output";
		
    		Path srcPath = Paths.get(outDir);
    		Path destPath = Paths.get(destDir);
    		System.out.println("MOVE " + outDir + " to " + destDir);
    		try {
				FileUtils.moveDirectory(new File(outDir), new File(destDir));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	}
    }
    public static CommandLine generateCMD(String[] args) {
    	Options options = new Options();
    	options.addOption(Option.builder("h").longOpt("help")
                .build());
        options.addOption(Option.builder("u").longOpt("username")
                .desc("Remote server username")
                .hasArg()
                .argName("USERNAME")
                .build());
        options.addOption(Option.builder("p").longOpt("password")
                .desc("Remote server password")
                .hasArg()
                .argName("PASSWORD")
                .build());
        options.addOption(Option.builder("d").longOpt("domain")
                .desc("Remote server ip")
                .hasArg()
                .argName("DOMAIN")
                .build());
        options.addOption(Option.builder("f").longOpt("filter")
                .desc("Jar path must contain this term to be included")
                .hasArg()
                .argName("FILTER")
                .build());
        Options javaGadgetOptions = Java_Gadget.createOptions();
        for(Option opt : javaGadgetOptions.getOptions()) {
        	options.addOption(opt);
        }
        options.addOption(Option.builder("o").longOpt("output")
                .desc("Output to folder")
                .hasArg()
                .argName("FOLDER")
                .build());
       
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            printUsage(formatter, options);
        }
        if(cmd.getOptions().length < 1)
        	printUsage(formatter, options);
        
        return cmd;

    }
    public static void interactiveMode(CommandLine cmd) {
    	Console console = System.console();
    	String scanType;
		String functionName;
		String folderPath;
		String action;
		String output;
		String outputFolder;
		String newLocalCmd = null;
		String removePrefix;
    	String localOrRemote;
    	while((localOrRemote = console.readLine("[L]ocal or [R]emote: (L)")).matches("(?i)l|r||") == false);
    	
    	File jar = new java.io.File(Java_Gadget_Kit.class.getProtectionDomain()
        		  .getCodeSource()
        		  .getLocation()
        		  .getPath());
        String jarName = jar.getName();
        final RemoteCalls rc = RemoteCalls.getInstance();
        
    	if(localOrRemote.matches("(?i)r")) {
    		String user;
    		String password;
    		String ip;
    		while(rc.isConnected == false) {
    			//clear screen
    			user = console.readLine("User: ");
    			password = new String(console.readPassword("Password: "));
    		    ip = console.readLine("Server (ex:10.0.0.35): ");
    		    rc.connect(user,  ip,  password);
    		    if(rc.isConnected == false) {
    		    	System.out.println("Connection Failed");
    		    }
    		}
    		
			//System.out.println("Jar Location: " + jar.toString());
			
			//remote call here
			String outFolder = cmd.getOptionValue("output");
			
			rc.sendCommand("rm -rf /var/kit/files/output");
			rc.sendCommand("mkdir -p /var/kit/files/output");
			rc.sendCommand("mkdir -p /var/kit/files/callgraph");
			String jarpath = "unknown.jar";
			try {
				jarpath = new File(Java_Gadget_Kit.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
			} catch (URISyntaxException e1) {
			
				// TODO Auto-generated catch block
				e1.printStackTrace();
				System.exit(3);
			}
			rc.sendFiles(jarpath, "/var/kit");
			System.out.println("Files uploaded complete!");
    	}
		
		ArrayList<String> argsArray = new ArrayList<String>();
		
		while(true) {
		    
			while((scanType = console.readLine("[S]tatic or [D]ynamic Scan or [I]nject into PID or [E]xit: (S)")).matches("(?i)s|i|d|e") == false);
    		
			if(scanType.matches("(?i)e")){
				System.out.println("Finished!");
		        System.exit(0);
			}
			else if(scanType.matches("(?i)s")) {
				System.out.println("Static\n");
				functionName = console.readLine("Target Function (ex: AClass:functionA): "); 
				folderPath = console.readLine("Directory To Search (ex: /var C:\\test): ");
				
				
				while((action = console.readLine("Action: [S]earch or output as [H]tml or [G]raphViz or [P]rettyprint: (S)")).matches("(?i)s|h|g|p||") == false);
				
				if(action.matches("(?i)s||")){
					System.out.println("Searching...");
					argsArray = new ArrayList<String>(Arrays.asList("-jp", "-v", "-s", functionName, "-f", folderPath));
					newLocalCmd = String.join(" ", argsArray);
					
					
				}
				else {
					//TODO VALIDATE FOLDER EXISTS ON SYSTEM
					outputFolder = console.readLine("Output Folder (ex: C:\test or /var/test): ");
					removePrefix = console.readLine("Remote Prefix: ");
					argsArray = new ArrayList<String>(Arrays.asList("-rp", removePrefix, "-rd", "-o", outputFolder, "-s", functionName, "-f", folderPath));
					
					System.out.println("Searching And Generating Output...");
					if(action.matches("(?i)h")){
						argsArray.add(0, "-i");
					}
					else if(action.matches("(?i)g||")){
						argsArray.add(0, "-gm");
					}
					else if(action.matches("(?i)p||")){
						argsArray.add(0, "-pp");
					}
					newLocalCmd =  String.join(" ", argsArray);
				}
				
				if (localOrRemote.matches("(?i)r")){
					newLocalCmd = String.format("java -jar /var/kit/%s %s", jarName, newLocalCmd);
		        	System.out.println(newLocalCmd);
		        	output = rc._sendCommand(newLocalCmd, true);
				}
				else {
					
					Options javaGadgetOptions = Java_Gadget.createOptions();
					String[] args = argsArray.toArray(new String[argsArray.size()]);
					cmd = generateCMD(args);
					mainLocalCall(javaGadgetOptions, cmd);
				}
			}
				
			else if(scanType.matches("(?i)d")) {
				System.out.println("Dynamic\n");
				if (localOrRemote.matches("(?i)r")){
					functionName = console.readLine("Target Function (ex: AClass:functionA): "); 
					newLocalCmd = String.format("java -cp /var/kit/%s com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Dynamic -s \"%s\"", jarName, functionName);

		        	System.out.println(rc.sendCommand(newLocalCmd));

				}
				else {
					functionName = console.readLine("Target Function (ex: AClass:functionA): "); 
					HashMap<String,String> options = new HashMap<String,String>();
					options.put("searchFunction", functionName);
					
					Java_Gadget_Dynamic.executeRequest(options);
				}

			}
			else {
				if (localOrRemote.matches("(?i)r")){
					String listPIDCommand = String.format("java -cp /var/kit/%s com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Injector -lpid", jarName);
					System.out.println(rc._sendCommand(listPIDCommand, true));
				}
				else {
					Java_Gadget_Injector.getJavaPIDList();
			        
				}
		        
				String pids = console.readLine("Enter PID (ex 123, 123;124;125): ");
				functionName = console.readLine("Target Function (ex: com.test.App;printText~com.test.App;main): "); 
				ArrayList<String> pidList = new ArrayList<String>();
				
				if(pids.matches("^(0|[1-9][0-9]*)$")) {
					//numeric pid				
					pidList.add(pids);
				}
				else if(pids.contains(";")) {
					//multiple pids
					pidList.addAll(Arrays.asList(pids.split(";")));
				}
				else {
					System.out.println("Can't handle entry for pid.");
				}
				if(pidList.size() > 0) {
					if (localOrRemote.matches("(?i)r")){
						//get user of process
						//ps -o user= -p <pid>
						//su - newuser -c 'process'
						//echo "2439;2433" | tr ";" "\n" | xargs -I '{}' ps -o user= -o pid=  -p '{}'
						//test 1233
						//test2 223
						
						String getUserNames = "echo '"+pids+"' | tr \";\" \"\\n\" | xargs -I '{}' ps -o user:25= -o pid=  -p '{}'";
						//System.out.println(getUserNames);
						getUserNames = rc.sendCommand(getUserNames);
						String[] items;
						ArrayList<String> newPids;
						HashMap<String, ArrayList<String>> pidUserMap = new HashMap<String, ArrayList<String>>();
						
						int len = getUserNames.split("\n").length;
						System.out.println(len);
						for (String pidStr : getUserNames.split("\n")) {							
							items = pidStr.split("\\s+");

							//if user in list
							if(pidUserMap.containsKey(items[0])) {
								pidUserMap.get(items[0]).add(items[1]);
							}
							else {
								newPids = new ArrayList<String>();
								newPids.add(items[1]);
								pidUserMap.put(items[0], newPids);
							}
						}

						//su - newuser -c 'process'
						String fullCommand = "";
						for (String user: pidUserMap.keySet()) {
							newLocalCmd = String.format("java -cp /var/kit/%s com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Injector -s \"%s\" -pid \"%s\"", jarName, functionName, String.join(";", pidUserMap.get(user)));
							fullCommand = String.format("su - %s -c '%s'", user, newLocalCmd);
							System.out.println(fullCommand);
							exitprocess = false;
							Runnable listenForInput = () -> { 				
					    	    while(exitprocess == false) {
					    	    	String out = console.readLine("Listening For Client Input ([E]xit): ");
					    	    	exitprocess = out.matches("(?i)e");
					    	    }
					    	    System.out.println("Exited");
					    	    rc.sendCommand("pkill -9 -f \"software_forensic_kit\"");    
					    	};
					    	Thread listenForInputThread = new Thread(listenForInput);
					    	listenForInputThread.start();
							System.out.println(rc._sendCommand(fullCommand, true));
							
							//pkill -9 -f "software_forensic_kit"
						}
					}
					else {
						Java_Gadget_Injector.inject(pidList, functionName);
					}
				}
			}
				
    	}
    }
}
