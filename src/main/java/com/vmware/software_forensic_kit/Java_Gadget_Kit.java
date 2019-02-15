/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.vmware.software_forensic_kit.java_gadget.Java_Gadget;
import com.vmware.software_forensic_kit.java_gadget.local.LocalCalls;
import com.vmware.software_forensic_kit.java_gadget.remote.RemoteCalls;

public class Java_Gadget_Kit {
	
	public static void printUsage(HelpFormatter formatter, Options options) {
		String footer = "Example Usage:\r\n" + 
        		"	>java -jar software_forensic_kit.jar -u root -d 10.160.157.187 -p test123 -s \"ExampleClass:functionA\" -f /var/www -im -rp my.class.path.\r\n" + 
        		"	or using wildcards * for filter\r\n" + 
        		"	>java -jar software_forensic_kit.jar -u root -d 10.160.157.187 -p test123 -s \"ExampleClass*functionA\" -f /var/www -pp -rp my.class.path. -o C:\\test\\output";
        formatter.setOptionComparator(null);
        formatter.printHelp("Software_Forensic_Kit", "", options, footer, true);

        System.exit(1);
	}
	
    public static void main(String[] args) {
    	
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
        	try {
				outDir = LocalCalls.getJarPath() + sep + String.format(outDir,  hour, minute, second);
			} catch (URISyntaxException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	
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
        	String filter = cmd.getOptionValue("filter");
        	String sep = System.getProperty("file.separator");
        	String localOutput = "files" + sep + "output";
        	String localCG = "files" + sep + "callgraph";
        	
        	ArrayList<String> jarList = LocalCalls.findJars(filter);
        	LocalCalls.makeDirsNearJar(localOutput);
        	LocalCalls.makeDirsNearJar(localCG);
        	
        	ArrayList<String> callGraphList = LocalCalls.createCallGraphs(jarList, localCG);
       
        	HashMap<String, String> map = new HashMap<String, String>();
            for (Option opt : cmd.getOptions()) {
            	if(javaGadgetOptions.hasOption(opt.getOpt()))
            		map.put(opt.getLongOpt(), cmd.getOptionValue(opt.getOpt()));
            }
        	
        	for(String callGraph : callGraphList) {
        		System.out.println("CALLGRAPH: " + callGraph);
        		Java_Gadget.executeRequestUsingCGFile(map, callGraph);
        	}
        	
        }
        
        System.out.println("Finished!");
        System.exit(0);
        

    }
}