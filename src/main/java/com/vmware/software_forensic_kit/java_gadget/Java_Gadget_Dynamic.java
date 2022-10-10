/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.vmware.software_forensic_kit.java_gadget.local.LocalCalls;

public class Java_Gadget_Dynamic{
	
	public static void printUsage(HelpFormatter formatter, Options options) {
		String footer = "Example Usage:\r\n" + 
        		"	>java -cp software_forensic_kit.jar com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Dynamic -s \"ExampleClass:functionA\" -im -rp my.class.path.  /home/test/testfile.jar\r\n" + 
        		"	or using wildcards * for filter\r\n" + 
        		"	>java -cp software_forensic_kit.jar com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Dynamic  -s \"ExampleClass*functionA\" -pp -rp my.class.path.  /var/test/example.jar ";
        formatter.setOptionComparator(null);
        formatter.printHelp("Java_Gadget_Dynamic [OPTIONS] <FILE>\nOptions include:", "", options, footer, true);
    
        System.exit(1);
	}
	public static Options createOptions() {
		Options options = new Options();
        options.addOption(Option.builder("s").longOpt("searchFunction")
                .desc("Function to search for")
                .hasArg()
                .argName("FUNCTION")
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
        
        HashMap<String, String> map = new HashMap<String, String>();
        for (Option opt : cmd.getOptions()) {
        	map.put(opt.getLongOpt(), cmd.getOptionValue(opt.getOpt()));
        }

        executeRequest(map);
        
    }
    
    public static void executeRequest(HashMap<String, String> options) {
    	
    	String sep = System.getProperty("file.separator");
    	String localCG = "files" + sep + "callgraph";
    	String callgraphFullPath = LocalCalls.getJarPath() + sep + localCG;

    	String funcName = options.get("searchFunction"); 
    	
    	ArrayList<String> output = LocalCalls._runCommand(new String[] {"/bin/sh", "-c", "pgrep -f java | xargs -I '{}' lsof -p '{}' | grep 'jar' | awk '{print $2\";\"$9}'"});
    	ArrayList<String> uniqueJars = new ArrayList<String>();
    	HashMap<String, ArrayList<String>> pidJarMap = new HashMap<String, ArrayList<String>>();
    	String mypid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
    	
        String[] items;
    	for(String line: output) {
    		items = line.split(";");
    		if(items[0] != mypid) {
	    		if(uniqueJars.contains(items[1]) == false)
	    			uniqueJars.add(items[1]);
	    		
	    		if(pidJarMap.containsKey(items[0]) == false) {
	    			ArrayList<String> newJarList = new ArrayList<String>();
	    			newJarList.add(items[1]);
	    			pidJarMap.put(items[0], newJarList);
	    		}
	    		else {
	    			ArrayList<String> tempJarList = pidJarMap.get(items[0]);
	    			tempJarList.add(items[1]);
	    			pidJarMap.put(items[0], tempJarList);
	    		}
    		}
    	}
    	System.out.println(String.format("PID running java: \n%s", String.join("\n", pidJarMap.keySet())));
    	
    	System.out.println(String.format("Creating CallGraphs for %d jars: \n", uniqueJars.size()));
    	LocalCalls.createCallGraphs(uniqueJars, localCG);

    	Map<String, String> jarsToCG = uniqueJars.stream().collect(Collectors.toMap(x -> String.format("%s%s", callgraphFullPath + sep, LocalCalls.jarFileToCallGraphFile(x)), x -> x.toString()));
    	//LocalCalls._runCommand(new String[] {"/bin/sh", "-c", "cwd"});
    	//TODO replace * with .* for grep
    	System.out.println(String.format("'grep -rl %s %s'", funcName, callgraphFullPath));
    	output = LocalCalls._runCommand(new String[] {"/bin/sh", "-c", String.format("grep -rl %s %s", funcName, callgraphFullPath)});
    	System.out.println(String.format("\n%s", String.join("\n", output) ));
    	
    	
    	HashMap<String, String> jarMapMatches = new HashMap<String, String>();
    	for(String key : jarsToCG.keySet()) {
    		if(output.contains(key)){
    			jarMapMatches.put(key, jarsToCG.get(key));
    		}
    	}
    	
    	ArrayList<String> matchedPids = new ArrayList<String>();
    	
    	for(String key : pidJarMap.keySet()) {
    		for (String value: jarMapMatches.values()) {
	    		if(pidJarMap.get(key).contains(value)) {
	    			//add it and break
	    			matchedPids.add(key);
	    			break;
	    		}
    		}
    	}
    	System.out.println(String.format("Matched PIDs: \n%s", String.join("\n", matchedPids)));
    }
    

}