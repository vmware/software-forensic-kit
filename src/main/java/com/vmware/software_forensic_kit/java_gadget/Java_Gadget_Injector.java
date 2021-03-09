package com.vmware.software_forensic_kit.java_gadget;

import java.io.Console;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import com.vmware.software_forensic_kit.java_gadget.local.LocalCalls;

public class Java_Gadget_Injector{
	public static boolean exitserver = false;
	
	public static void printUsage(HelpFormatter formatter, Options options) {
		String footer = "Example Usage:\r\n" + 
        		"	>java -cp software_forensic_kit.jar com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Injector -s \"ExampleClass;functionA\" -pid 123\r\n" + 
        		"	or using wildcards * for filter\r\n" + 
        		"	>java -cp software_forensic_kit.jar com.vmware.software_forensic_kit.java_gadget.Java_Gadget_Injector  -s \"ExampleClass;functionA\" -pid \"123;124;1235\"";
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
        options.addOption(Option.builder("pid").longOpt("PID")
                .desc("PID(s) to inject into")
                .hasArg()
                .argName("pid")
                .build());
        options.addOption(Option.builder("lpid").longOpt("LPID")
                .desc("List Java PID(s)")
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
        
        if(cmd.hasOption("lpid")) {
        	getJavaPIDList();
        	System.exit(1);
        }
        ArrayList<String> pidList = new ArrayList<String> ();
        String pids = cmd.getOptionValue("PID");
        if(pids.matches("^(0|[1-9][0-9]*)$")) {			
			pidList.add(pids);
		}
		else if(pids.contains(";")) {
			pidList.addAll(Arrays.asList(pids.split(";")));
		}
        
        inject(pidList, cmd.getOptionValue("searchFunction"));
        
    }
    public static void getJavaPIDList() {
    	
    	//if linux
    	//ps aux | grep java | awk {'print $2 " " $1 " " $11'}
    	//windows
    	//powershell -c "Get-WmiObject Win32_Process -Filter \"name = 'java.exe'\" | Select-Object ProcessId,CommandLine"
    	ArrayList<String> output = new ArrayList<String>();
    	
    	if(LocalCalls.OS.startsWith("Windows")) { output = LocalCalls._runCommand(new String[] {"powershell", "-c", "\"Get-WmiObject Win32_Process -Filter \\\"name = 'java.exe'\\\" | Select-Object ProcessId,CommandLine\""});}
    	else { output = LocalCalls._runCommand(new String[] {"/bin/sh", "-c", "ps aux | grep java | awk {'print $2 \" \" $1 \" \" $11'}"});}
    	
    	for(String line: output) {System.out.println(line);}
    	
    	//VirtualMachine doesn't list jvms not started by this user.
    	//List<VirtualMachineDescriptor> jvms = VirtualMachine.list();
        //System.out.println("Processes Running Java:");
        //for (VirtualMachineDescriptor jvm : jvms) {System.out.println(jvm.id() + " - " + jvm.displayName());}
    }
	public static void inject(ArrayList<String> matchedPids, String classMethodsPath) {
	    List<VirtualMachineDescriptor> jvms = VirtualMachine.list();
		String sep = System.getProperty("file.separator");
		exitserver = false;
		//Server must be created before attaching javaagent
		try {
			ServerSocket server = new ServerSocket(31337);
			Runnable runnable = () -> { 
	    	    System.out.println("Server started on port 31337.");
	    	    Console console = System.console();
	    	   
	    	    while(exitserver == false) {
	    	    	String out = console.readLine("Listening For Client Input: [E]xit");
	    	    	exitserver = out.matches("(?i)e");
	    	    	System.out.println(exitserver);
	    	    }
	    	    System.out.println("Exited");
	    	    try {
					server.close();
					System.exit(0);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	    	    
	    	};
	    	Thread t = new Thread(runnable);
	    	t.start();
	    	
	    	VirtualMachine vm = null;
	    	
	    	String jarName = new java.io.File(Java_Gadget_Dynamic.class.getProtectionDomain()
	       		  .getCodeSource()
	       		  .getLocation()
	       		  .getPath())
	       		  .getName();
	    	System.out.println(String.format("[[%s]]", classMethodsPath));
	    	for(String pid : matchedPids) {
	    	
	    			System.out.println(String.format("{%s}", pid));
	    	}
	    	for(String pid : matchedPids) {
	    		try {
	    			
	    			System.out.println(String.format("{%s}", pid));
	                vm = VirtualMachine.attach(pid);
	                vm.loadAgent(LocalCalls.getJarPath() + sep + jarName, classMethodsPath);
	                vm.detach();
	            } catch (Exception e) {
	                System.out.println(e);
	                System.out.println(String.format("Couldn't attach to: {%s}", pid));
	            }
	    	
	    	}
	    	
	    	Runnable runnable2 = () -> {
	    		try {
	    	
			    	while(exitserver == false){ 
			    	
			             Socket socket = server.accept();
			             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
			             String message = "";
			             while(true) {
			             	try {
			             		//try to read all objects and catch fail if no more objects
			             		message = (String) ois.readObject();
			             		System.out.println("" + message);
			             	}
			             	catch (EOFException e) {
			             		 break;
			             	} catch (ClassNotFoundException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
			             }
			
			             ois.close();
			             socket.close();
			             if(message.equalsIgnoreCase("exit")) break;
			    		
			         }
			         System.out.println("Shutting down socket server!!");
			         //close the ServerSocket object
			         server.close();
	    		}
	    		catch(Exception e) {}
	    	};
	    	Thread t2 = new Thread(runnable2);
	    	t2.start();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
    	
	}
}