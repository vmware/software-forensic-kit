/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.vmware.software_forensic_kit.java_gadget.local.LocalCalls;

public class Java_Gadget{
	
	public static void printUsage(HelpFormatter formatter, Options options) {
		String footer = "Example Usage:\r\n" + 
        		"	>java -cp software_forensic_kit.jar com.vmware.software_forensic_kit.java_gadget.Java_Gadget -s \"ExampleClass:functionA\" -hm -rp my.class.path.  /home/test/testfile.jar\r\n" + 
        		"	or using wildcards * for filter\r\n" + 
        		"	>java -cp software_forensic_kit.jar com.vmware.software_forensic_kit.java_gadget.Java_Gadget  -s \"ExampleClass*functionA\" -pp -rp my.class.path.  /var/test/example.jar ";
        formatter.setOptionComparator(null);
        formatter.printHelp("Java_Gadget [OPTIONS] <FILE>\nOptions include:", "", options, footer, true);
    
        System.exit(1);
	}
	public static Options createOptions() {
		Options options = new Options();
        options.addOption(Option.builder("s").longOpt("searchFunction")
                .desc("Function to search for")
                .hasArg()
                .argName("FUNCTION")
                .build());
        options.addOption(Option.builder("cd").longOpt("depth")
                .desc("Max callgraph depth (default is 8)")
                .hasArg()
                .argName("NUM")
                .build());
        options.addOption(Option.builder("rp").longOpt("removePrefix")
                .desc("Remove Prefix from callgraph text")
                .hasArg()
                .build());
        options.addOption(Option.builder("rd").longOpt("removeDuplicates")
                .desc("Remove Duplicate Paths")
                .build());
        options.addOption(Option.builder("jp").longOpt("justPrint")
                .desc("Print output to console")
                .build());
        options.addOption(Option.builder("pp").longOpt("prettyPrint")
                .desc("Pretty Print output to console")
                .build());
        options.addOption(Option.builder("g").longOpt("graphViz")
                .desc("Output for Graphviz")
                .build());
        options.addOption(Option.builder("gm").longOpt("graphVizM")
                .desc("Output for Graphviz Multiple")
                .build());
        options.addOption(Option.builder("hi").longOpt("html")
                .desc("Output for HTML - https://visjs.org")
                .build());
        options.addOption(Option.builder("hm").longOpt("htmlM")
                .desc("Output for HTML Multiple - https://visjs.org")
                .build());
        options.addOption(Option.builder("cgf").longOpt("callgraphFile")
                .desc("Passing in CallGraph file instead of jar(s)")
                .build());
        options.addOption(Option.builder("I").longOpt("interactive")
                .desc("Interactive Mode")
                .build());
        options.addOption(Option.builder("v").longOpt("verbose")
                .desc("Verbose")
                .build());
        
        return options;
	}
    public static void main(String[] args) {
    	
    	Options options = createOptions();
       
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
        
        //String user = cmd.getOptionValue("username");

        //TODO: parse options send options to static method. 
        // The static method will execute the request. 
        HashMap<String, String> map = new HashMap<String, String>();
        for (Option opt : cmd.getOptions()) {
        	map.put(opt.getLongOpt(), cmd.getOptionValue(opt.getOpt()));
        }
        
        List<String> leftover = cmd.getArgList();
        for(String l : leftover) {
        	System.out.println(l);
        }
        executeRequest(map, leftover.get(0));
        
    }
    
    public static void executeRequest(HashMap<String, String> options, String jarFile) {
    	
    	String sep = System.getProperty("file.separator");
    	String localCG = "files" + sep + "callgraph";

    	String callgraphFullPath = "";
    	ArrayList<String> jarList = new ArrayList<String>(Arrays.asList(jarFile));
    	
    	if(options.containsKey("callgraphFile") == false) {
	    	LocalCalls.createCallGraphs(jarList, localCG);
	    	
	    	String callgraphOut = LocalCalls.jarFileToCallGraphFile(jarFile);
	    	
	    	String jarPath = LocalCalls.getJarPath();
			
    	
	    	callgraphFullPath = jarPath + sep + localCG + sep + callgraphOut;
    	}
    	else {
    		callgraphFullPath = jarFile;
    	}
    	System.out.println("PATH: " + callgraphFullPath);
    	executeRequestUsingCGFile(options, callgraphFullPath);
    	System.out.println("DONE");
    		
    	
    }
    public static void executeRequestUsingCGFile(HashMap<String, String> options, String localCG){
    	//System.out.println(options);
    	CallGraphAnalysis gca = new CallGraphAnalysis(localCG, options);
    	gca.run();
    }
}