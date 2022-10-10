package com.vmware.software_forensic_kit.java_gadget.local;

import java.lang.reflect.Modifier;

import org.apache.bcel.classfile.Constant;
import org.apache.bcel.classfile.ConstantPool;
import org.apache.bcel.classfile.EmptyVisitor;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.MethodGen;

public class JarCallGraphClassVisitor extends EmptyVisitor{
	
		private JavaClass javaClazz;
		private ConstantPoolGen constants;
		
		public JarCallGraphClassVisitor(JavaClass javaClazz) {
			this.javaClazz = javaClazz;
			constants = new ConstantPoolGen(javaClazz.getConstantPool());
		}
	    public void visitJavaClass() {
	        this.javaClazz.getConstantPool().accept(this);
	        Method[] methods = this.javaClazz.getMethods();
	        for (int i = 0; i < methods.length; i++)
	            methods[i].accept(this);
	    }

	    public void visitConstantPool(ConstantPool constantPool) {
	        for (int i = 0; i < constantPool.getLength(); i++) {
	            Constant constant = constantPool.getConstant(i);
	            if (constant == null)
	                continue;
	            if (constant.getTag() == 7) {
	                String referencedClass = 
	                    constantPool.constantToString(constant);
	                System.out.println(String.format("C:" +  Modifier.toString(javaClazz.getModifiers()).replaceAll(" ", ",") + ":" + javaClazz.getClassName() + " %s",
	                        referencedClass));
	            }
	        }
	    }

	    public void visitMethod(Method method) {
	 
	        MethodGen classMethodGen = new MethodGen(method, javaClazz.getClassName(), constants);
	        if(classMethodGen.isNative() == false && classMethodGen.isAbstract() == false) {
	        	new JarCallGraphMethodVisitor(classMethodGen, javaClazz).startParsing();
	        }
	    	
	    }

	}