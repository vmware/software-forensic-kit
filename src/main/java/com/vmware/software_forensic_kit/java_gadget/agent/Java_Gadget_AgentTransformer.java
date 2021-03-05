/***************************************************
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget.agent;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.util.CheckClassAdapter;

public class Java_Gadget_AgentTransformer implements ClassFileTransformer {
	public String className;
	public String methodName;
	public Java_Gadget_AgentTransformer(String className, String methodName) {
		this.className = className;		
		this.methodName = methodName;
		
	}
	@Override
    public byte[] transform(ClassLoader loader, String className, Class classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
		String newClassName = className.replace("/", ".");
		
		//skip if our application found
		if(newClassName.contains("software_forensic_kit"))
			return classfileBuffer;
		
		// skip if classname doesn't equal expected classname
		if(newClassName.equals(this.className) == false)
			return classfileBuffer;

		
		byte[] result = classfileBuffer;
        try {
            // Create class reader from buffer
            ClassReader reader = new ClassReader(classfileBuffer);
            // Make writer
            ClassWriter cw = new ClassWriter(0);

            ClassVisitor profiler = new HelpClassVisitor(cw, className, this.methodName);
         
            CheckClassAdapter checker = new CheckClassAdapter(profiler, true);
            // Add the class adapter as a modifier
            reader.accept(checker, 0);
            result = cw.toByteArray();
            /*
             * DEBUG ASM CODE:*/
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            CheckClassAdapter.verify(new ClassReader(cw.toByteArray()), true, pw);
            System.out.println("Returning reinstrumented class: " + newClassName + " : " + this.className);
            System.out.println(sw.toString());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;

	}


}



