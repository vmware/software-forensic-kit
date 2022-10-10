package com.vmware.software_forensic_kit.java_gadget.local;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.classfile.JavaClass;


public class JarCallGraph{
	
	public static void main(String[] args) {
		JarCallGraph.parseJars(args);
	}
	public static void parseJars(String[] jarList) {
		
		for (String jarFile : jarList) {
			parseJar(jarFile);
		}
	}
	public static void parseJar(String jarFile) {
		try {
		
			JarCallGraphClassVisitor javaClassV;
			JarFile jarF = new JarFile(new File(jarFile));
			
			Enumeration<JarEntry> jarEntries = jarF.entries();
			JarEntry jarEntry = jarEntries.nextElement();
			while(jarEntry != null) {
				if(jarEntry.isDirectory() == false && jarEntry.getName().endsWith(".class")) {
					JavaClass javaClazz = new ClassParser(jarFile, jarEntry.getName()).parse();
					javaClassV = new JarCallGraphClassVisitor(javaClazz);
					javaClassV.visitJavaClass();
				}
				if(jarEntries.hasMoreElements())
					jarEntry = jarEntries.nextElement();
				else
					jarEntry = null;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	}
	
	
}