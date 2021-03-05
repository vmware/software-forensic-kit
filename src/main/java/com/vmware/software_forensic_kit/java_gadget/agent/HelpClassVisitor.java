/***************************************************
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget.agent;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public class HelpClassVisitor extends ClassVisitor {
    private String className;
    private String methodName;
           
    public HelpClassVisitor(ClassVisitor cv, String pClassName, String methodName) {
	super(Opcodes.ASM5, cv);
		this.className = pClassName;
		this.methodName = methodName;
    }
                                                         
    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
    	MethodVisitor mv = super.visitMethod(access, name, desc, signature,
                exceptions);
    	
   
    	if(name.equals(this.methodName)) {
    	System.out.println(String.format("Software_Forensic  method %s - %s", name, desc));
    	
    	 try {
    		 String newClassName = className.replace("/", ".");
    		    Class<?> act = Class.forName(newClassName);
    		    System.out.println(newClassName);
    		    System.out.println(act.getName());
    		    System.out.println(act.getDeclaredMethods());
    		    Method fld[] = act.getDeclaredMethods();
    	         for (int i = 0; i < fld.length; i++)
    	         {
    	        	 if(fld[i].getName().equals(this.methodName)) {
    	             System.out.println("Method Name is : " + fld[i].getName());
    	             Parameter paraM[] = fld[i].getParameters();
    	             for (int g = 0; g<paraM.length; g++) {
    	            	 System.out.println("Variable Name is : " + paraM[g].toString());
    	             }
    	        	 }
    	         }   
    		 } catch (ClassNotFoundException e) {
    		        e.printStackTrace();
    		}
    	
        return new HelpMethodVisitor(access, mv, name, className, desc);
    	}
    	return mv;
    
    } 
    
   
   
}
