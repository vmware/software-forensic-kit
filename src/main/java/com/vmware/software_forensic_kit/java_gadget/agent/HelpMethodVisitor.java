package com.vmware.software_forensic_kit.java_gadget.agent;

import static org.objectweb.asm.Opcodes.ALOAD;
import static org.objectweb.asm.Opcodes.ASTORE;
import static org.objectweb.asm.Opcodes.DUP;
import static org.objectweb.asm.Opcodes.GETSTATIC;
import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;
import static org.objectweb.asm.Opcodes.LLOAD;
import static org.objectweb.asm.Opcodes.NEW;
import static org.objectweb.asm.Opcodes.SIPUSH;

import java.lang.reflect.Parameter;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.GeneratorAdapter;

public class HelpMethodVisitor extends GeneratorAdapter {

	public String methodName;
	public String desc;
	public String className;
	public Parameter paramM[];
	public boolean isAnnotationPresent = false;

	public Label tryStart = new Label();
	public Label tryEnd = new Label();
	public Label catchStart = new Label();
	public Label catchEnd = new Label();
	public HelpMethodVisitor(int access, MethodVisitor mv, String name, String className, String desc, Parameter paramM[]) {
		super(Opcodes.ASM5, mv, access, name, desc);
		this.methodName = name;
		this.desc = desc;
		this.className = className;
		this.paramM =  paramM;
		System.out.println(this.methodName);
		System.out.println(this.desc);
	}

	/*public void visitLocalVariable​(java.lang.String name, java.lang.String descriptor, java.lang.String signature, Label start, Label end, int index) {
		super.visitLocalVariable(name, descriptor, signature, start, end, index);
		System.out.println(String.format("THERE??? %s %d", name, index));
		this.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		this.visitVarInsn(LLOAD, index);
		this.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(J)V", false);
	}
	
	public void visitVarInsn​(int opcode, int var) {
		super.visitVarInsn(opcode, var);
		System.out.println(String.format("HERE??? %d %d", opcode, var));
		this.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		this.visitVarInsn(LLOAD, var);
		this.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(J)V", false);
	}*/
	@Override
	public void visitCode()  {
		
        super.visitCode();
       
        System.out.println("visitCode");
        this.visitTryCatchBlock(tryStart, tryEnd, catchStart, "java/lang/Exception");
        this.visitLabel(tryStart);
       
        int socketVal = this.newLocal(Type.LONG_TYPE);
		int oosVal = this.newLocal(Type.LONG_TYPE);
		System.out.println("::"+socketVal +"::"+oosVal);

		// create socket 
		this.visitTypeInsn(NEW, "java/net/Socket");
		this.visitInsn(DUP);
		this.visitLdcInsn("127.0.0.1");
		this.visitIntInsn(SIPUSH, 31337);
		this.visitMethodInsn(INVOKESPECIAL, "java/net/Socket", "<init>", "(Ljava/lang/String;I)V", false);
		
		this.visitVarInsn(ASTORE, socketVal);

		this.visitTypeInsn(NEW, "java/io/ObjectOutputStream");
		this.visitInsn(DUP);
		this.visitVarInsn(ALOAD, socketVal);
		this.visitMethodInsn(INVOKEVIRTUAL, "java/net/Socket", "getOutputStream", "()Ljava/io/OutputStream;", false);
		this.visitMethodInsn(INVOKESPECIAL, "java/io/ObjectOutputStream", "<init>", "(Ljava/io/OutputStream;)V", false);
		this.visitVarInsn(ASTORE, oosVal);
		this.visitVarInsn(ALOAD, oosVal);
		
		//output enter method {'method':'', 'state':'enter'...}
		this.visitLdcInsn(String.format("{'Method':'%s','State':'Enter', 'Desc':'%s'}", this.methodName, this.desc));
		this.visitMethodInsn(INVOKEVIRTUAL, "java/io/ObjectOutputStream", "writeObject", "(Ljava/lang/Object;)V", false);
		this.visitVarInsn(ALOAD, oosVal);
		
		//print object parameters
		//TODO: support int/char/long/etc...StringBuilder.append functions
		//Z for boolean, C for char, B for byte, S for short, I for int, F for float, J for long and D for double.
		if(socketVal > 0) {
			
			System.out.println(socketVal);
			Type[] args = Type.getArgumentTypes(this.desc);
			for(int i = 0; i<args.length; i++) {

				this.visitTypeInsn(NEW, "java/lang/StringBuilder");
				this.visitInsn(DUP);
				this.visitLdcInsn("{'param"+i+"':'" + paramM[i] + "', 'value':'");
				
				this.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
				this.loadArg(i);
				this.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", String.format("(%s)Ljava/lang/StringBuilder;", args[i].getDescriptor()), false);

					
				this.visitLdcInsn("'}");
				this.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
				this.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
				this.visitMethodInsn(INVOKEVIRTUAL, "java/io/ObjectOutputStream", "writeObject", "(Ljava/lang/Object;)V", false);
				this.visitVarInsn(ALOAD, oosVal);
			}
		}
		//output enter method {'method':'', 'state':'exit'...}
		this.visitLdcInsn(String.format("{'Method':'%s','State':'Exit', 'Desc':'%s'}", this.methodName, this.desc));

		this.visitMethodInsn(INVOKEVIRTUAL, "java/io/ObjectOutputStream", "writeObject", "(Ljava/lang/Object;)V", false);
		this.visitVarInsn(ALOAD, oosVal);
		this.visitMethodInsn(INVOKEVIRTUAL, "java/io/ObjectOutputStream", "close", "()V", false);
		this.visitLabel(tryEnd);
        // visit normal execution exit block
        this.visitJumpInsn(Opcodes.GOTO, catchEnd);

        // visit catch exception block
        this.visitLabel(catchStart);
        this.visitVarInsn(ASTORE, oosVal);
        this.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		this.visitLdcInsn("Error: Software_Forensic_Kit Agent Code");
		this.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);

		//On error we either exit with null or ex
		/*if(this.desc.endsWith("V"))
			this.visitInsn(RETURN);
		else {
			this.visitInsn(ACONST_NULL);
			this.visitInsn(ARETURN);
		}*/
        // exit from this dynamic block
        this.visitLabel(catchEnd);

        //this.visitJumpInsn(Opcodes.GOTO, catchEnd);

	}  
 

	@Override
    public void visitMaxs(int maxStack, int maxLocals) {
	  super.visitMaxs(maxStack+8, maxLocals);
    }
}

