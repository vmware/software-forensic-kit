/***************************************************
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget.local;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;

class LocalFileVisitor implements FileVisitor<Path>{

	public boolean printToConsole = false;
	public String endsWith = "";
	public String filter = "";
	ArrayList<String> jarList;
	public LocalFileVisitor(boolean printToConsole, String endsWith, String filter) {
		this.printToConsole = printToConsole;
		this.filter = filter;
		this.endsWith = endsWith;
		this.jarList = new ArrayList<String>();
	}
    private long filesReviewed = 0;
    private long filesPassed = 0;
    @Override
    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
       return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
    	filesReviewed++;
    	String fileString = file.toString();
    	
        if(fileString.endsWith(endsWith) && fileString.contains(filter)) {
        	filesPassed++;
        	jarList.add(fileString);
        }
        return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
        return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
       return FileVisitResult.CONTINUE;
    }

    public long getFilesPassedCount() {
        return filesPassed;
    }
    public long getFilesReviewedCount() {
        return filesReviewed;
    }
    public ArrayList<String> jarList() {
        return jarList;
    }
}