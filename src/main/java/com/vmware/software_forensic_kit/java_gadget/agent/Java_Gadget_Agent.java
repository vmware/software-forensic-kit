/***************************************************
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget.agent;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.util.ArrayList;


public class Java_Gadget_Agent {

	public static void premain(String args, Instrumentation instrumentation) throws ClassNotFoundException, UnmodifiableClassException {

	    //"com.simple.test.App;printText"
    	String[] newArgs = {args};
    	ArrayList<Class<?>> newClasses = new ArrayList<Class<?>>();
    	if(args.contains("~"))
    		newArgs = args.split("~");
	    for(String combo : newArgs) {
	    	String[] classMethod = combo.split(";");
	    	newClasses = new ArrayList<Class<?>>();
	    	System.out.println(String.format("Searching for %s", classMethod[0]));
	    	for(Class<?> clazz: instrumentation.getAllLoadedClasses()) {
        	    if(clazz.getName().equals(classMethod[0])) {
        	    	 System.out.println(String.format("ADDED: %s", clazz.getName()));
        	    	newClasses.add(clazz);
        	    }
            }
	    	
	    	for (Class<?> classObj : newClasses) {

  				instrumentation.addTransformer(new Java_Gadget_AgentTransformer(classObj.getName(), classMethod[1]), true );        		  
    		    
    		    try {
    		    	instrumentation.retransformClasses(classObj);
                } catch (Exception e) {
                    System.out.println("Failed to redefine class!");
                    System.out.println(e);
                    e.printStackTrace();
               
                }
    		    System.out.println(String.format("Software Forensic Kit: Class %s found! Transformed!", classObj.getName()));
		    	
	    	}
	    }
    }
	public static void agentmain(String args, Instrumentation instrumentation) throws IOException, ClassNotFoundException, UnmodifiableClassException {
	    premain(args, instrumentation);
    }
	
	
}