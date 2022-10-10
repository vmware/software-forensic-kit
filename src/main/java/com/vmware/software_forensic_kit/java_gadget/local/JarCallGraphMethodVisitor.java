package com.vmware.software_forensic_kit.java_gadget.local;

import java.lang.reflect.Modifier;
import java.util.stream.Stream;

import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.ConstantPushInstruction;
import org.apache.bcel.generic.EmptyVisitor;
import org.apache.bcel.generic.INVOKEDYNAMIC;
import org.apache.bcel.generic.INVOKEINTERFACE;
import org.apache.bcel.generic.INVOKESPECIAL;
import org.apache.bcel.generic.INVOKESTATIC;
import org.apache.bcel.generic.INVOKEVIRTUAL;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionConst;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;
import org.apache.bcel.generic.MethodGen;
import org.apache.bcel.generic.ReturnInstruction;
import org.apache.bcel.generic.Type;

public class JarCallGraphMethodVisitor extends EmptyVisitor{
    JavaClass javaClazz;
    private String outputFormat;
    private MethodGen classMethodGen;
    private ConstantPoolGen classConstantPoolGen;
    

	public JarCallGraphMethodVisitor(MethodGen classMethodGen, JavaClass javaClazz ) {
        this.javaClazz = javaClazz;
        this.classMethodGen = classMethodGen;
        this.classConstantPoolGen = this.classMethodGen.getConstantPool();
        this.outputFormat = "M:" + Modifier.toString(classMethodGen.getModifiers()).replaceAll(" ", ",") + ":" + javaClazz.getClassName() + ":" + classMethodGen.getName() + "(" + argumentList(classMethodGen.getArgumentTypes()) + ")"
	            + " " + "(%s)%s:%s(%s)";
    	
    }
    private String argumentList(Type[] arguments) {
    	String[] typeStrings = Stream.of(arguments).map(Type::toString).toArray(String[]::new);
    	return String.join(" ", typeStrings);
    }

    public void startParsing() {

        InstructionHandle instH = classMethodGen.getInstructionList().getStart(); 
        Instruction instruction;
        while(instH != null) {
            instruction = instH.getInstruction();
            
            if (visitInstruction(instruction) == false)
            	instruction.accept(this);
            instH = instH.getNext();
        }
         
    }
	private boolean visitInstruction(Instruction i) {
        short opcode = i.getOpcode();
        return ((InstructionConst.getInstruction(opcode) != null)
                && !(i instanceof ConstantPushInstruction) 
                && !(i instanceof ReturnInstruction));
    }
	public void genericSystemOut(InvokeInstruction i, String letter) {
		if(i != null && classConstantPoolGen != null)
		 System.out.println(String.format(outputFormat,letter,i.getReferenceType(classConstantPoolGen),i.getMethodName(classConstantPoolGen),argumentList(i.getArgumentTypes(classConstantPoolGen))));  
	}

    @Override
    public void visitINVOKEVIRTUAL(INVOKEVIRTUAL i) {
        genericSystemOut(i, "M");
    }

    @Override
    public void visitINVOKEINTERFACE(INVOKEINTERFACE i) {
    	genericSystemOut(i, "I");
    }

    @Override
    public void visitINVOKESPECIAL(INVOKESPECIAL i) {
    	genericSystemOut(i, "O");
    }

    @Override
    public void visitINVOKESTATIC(INVOKESTATIC i) {
    	genericSystemOut(i, "S");
    }

    @Override
    public void visitINVOKEDYNAMIC(INVOKEDYNAMIC i) {
    	genericSystemOut(i, "D");
    }
}