package com.vmware.software_forensic_kit.java_gadget.agent;

import static org.objectweb.asm.Opcodes.ACONST_NULL;
import static org.objectweb.asm.Opcodes.ALOAD;
import static org.objectweb.asm.Opcodes.ARETURN;
import static org.objectweb.asm.Opcodes.ASTORE;
import static org.objectweb.asm.Opcodes.DUP;
import static org.objectweb.asm.Opcodes.GETSTATIC;
import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;
import static org.objectweb.asm.Opcodes.NEW;
import static org.objectweb.asm.Opcodes.RETURN;
import static org.objectweb.asm.Opcodes.SIPUSH;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.LocalVariablesSorter;

public class HelpMethodVisitor extends LocalVariablesSorter {

	public String methodName;
	public String desc;
	public boolean isAnnotationPresent = false;


	public Label tryStart = new Label();
	public Label tryEnd = new Label();
	public Label catchStart = new Label();
	public Label catchEnd = new Label();
	public HelpMethodVisitor(int access, MethodVisitor mv, String name, String className, String desc) {
		super(Opcodes.ASM5, access, desc, mv);
		this.methodName = name;
		this.desc = desc;
	}

	
	@Override
	public void visitCode()  {
		
        super.visitCode();
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
		if(socketVal > 0) {
			for(int i = 0; i<socketVal; i++) {

				this.visitTypeInsn(NEW, "java/lang/StringBuilder");
				this.visitInsn(DUP);
				this.visitLdcInsn("{'param"+i+"':'");
				this.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
				this.visitVarInsn(ALOAD, i);
				this.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/Object;)Ljava/lang/StringBuilder;", false);
					
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

