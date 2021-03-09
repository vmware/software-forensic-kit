/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CallGraphNode {
	
	public CallGraphNode parent;
	public String data;
	public ArrayList<CallGraphNode> children = new ArrayList<CallGraphNode>();
	
	public CallGraphNode(String data) {
		this.data = data;
	}
	public String toString() {
		return this.data.toString();
	}
	
	public void addChild(CallGraphNode child) {
		child.parent = this;
		children.add(child);
	}
	
	public String cleanData(String removeFromStart) {
		String output = this.toString();
		if(removeFromStart != null && output.startsWith(removeFromStart)) {
			output = output.substring(removeFromStart.length());	
		}
		List<String> specialChars = Arrays.asList("()", "()");
		for(String chars : specialChars) {
			output = output.replaceAll(chars, "");
		}
		output = output.replaceAll(",", "_");
		output = output.replaceAll("__", "_");
		return output;
	}
	private ArrayList<CallGraphNode> findLeafs() {
		ArrayList<CallGraphNode> leafs = new ArrayList<CallGraphNode>();
		
		if(children.size() == 0) {
			return new ArrayList<CallGraphNode>(Arrays.asList(this));
		}
		else{
			for(CallGraphNode child : children) {
				leafs.addAll(child.findLeafs());
			}
		}
		
		
		return leafs;
	}
	public void prettyPrint(int maxDepth, String removeFromStart, boolean removeDuplicates) {
		ArrayList<CallGraphNode> leafs = findLeafs();
		
		for(CallGraphNode leafNode : leafs) {
			String output = leafNode.data;
			if(removeFromStart != null && output.startsWith(removeFromStart)) {
				output = output.substring(removeFromStart.length());	
			}
			
			int i = 0;
			while(leafNode.parent != null) {
				String parentOut = leafNode.parent.data;
				if(removeFromStart != null && parentOut.startsWith(removeFromStart)) {
					parentOut = parentOut.substring(removeFromStart.length());	
				}
				output += "\n\t -> " + parentOut;
				leafNode = leafNode.parent;
				
			}
			System.out.println(output + "\n#####################################################################################################################\n\n");
			
		}

	}
	public void justPrint(int maxDepth, String removeFromStart, boolean removeDuplicates) {
		ArrayList<CallGraphNode> leafs = findLeafs();
		
		for(CallGraphNode leafNode : leafs) {
			String output = leafNode.data;
			if(removeFromStart != null && output.startsWith(removeFromStart)) {
				output = output.substring(removeFromStart.length());	
			}
			
			int i = 0;
			while(leafNode.parent != null) {
				String parentOut = leafNode.parent.data;
				if(removeFromStart != null && parentOut.startsWith(removeFromStart)) {
					parentOut = parentOut.substring(removeFromStart.length());	
				}
				output += "\n" + parentOut;
				leafNode = leafNode.parent;
				
			}
			System.out.println(output + ";");
		}

	}

	public ArrayList<String> htmlandgraphvizMultiple(boolean returnJSON, int maxDepth, String removeFromStart, boolean removeDuplicates) {

		ArrayList<CallGraphNode> leafNodes = findLeafs();
		ArrayList<String> totals = new ArrayList<String>();
		ArrayList<String> outlines = new ArrayList<String>();
		int i = 0;
		String output = "";
		
		
		
		
		for (CallGraphNode leafNode : leafNodes) {
			i += 1;
			if(returnJSON == false)
				output = String.format("digraph leaf%d {\nratio=compress\n", i);
			else 
				output = "[";
			outlines = new ArrayList<String>();
			
			while(leafNode.parent != null) {
				
				String leafdata = leafNode.cleanData(removeFromStart);
				String pleafdata = leafNode.parent.cleanData(removeFromStart);
				String line = "";
				if(!leafdata.equals(pleafdata) ) {
					if(returnJSON == false) {
						line = String.format("\n%s -> %s ;" , leafdata, pleafdata);
					}
					else {
						line = String.format("{\"from\": \"%s\", \"to\": \"%s\"}," , leafdata, pleafdata);
					}
					if(outlines.contains(line) == false) {
						outlines.add(line);
					}
				}
				leafNode = leafNode.parent;
			}
		
			if(removeDuplicates) { 
				Set<String> set = new HashSet<String>();
				set.addAll(outlines);
				outlines.clear();
				outlines.addAll(set);
			
			}
			
			output += String.join("", outlines);
			
			if(returnJSON) {
				totals.add(output.substring(0, output.length() -1) + "]");
			}
			else {
				totals.add(output + "\n}\n");
			}
		}
		return totals;
	}
	public ArrayList<String> htmlandgraphviz(boolean returnJSON, int maxDepth, String removeFromStart, boolean removeDuplicates) {

		ArrayList<CallGraphNode> leafNodes = findLeafs();
		ArrayList<String> totals = new ArrayList<String>();
		ArrayList<String> outlines = new ArrayList<String>();
		int i = 0;
		String output = "";
		
		if(returnJSON == false)
			output = String.format("digraph leaf%d {\nratio=compress\n", i);
		else 
			output = "[";
		
		
		for (CallGraphNode leafNode : leafNodes) {
			i += 1;
			
			while(leafNode.parent != null) {
				
				String leafdata = leafNode.cleanData(removeFromStart);
				String pleafdata = leafNode.parent.cleanData(removeFromStart);
				if(!leafdata.equals(pleafdata) ) {
					if(returnJSON == false)
						outlines.add(String.format("\n%s -> %s ;" , leafdata, pleafdata));
					else
						outlines.add(String.format("{\"from\": \"%s\", \"to\": \"%s\"}," , leafdata, pleafdata));
				}
				leafNode = leafNode.parent;
			}
		}
		if(removeDuplicates) { 
			Set<String> set = new HashSet<String>();
			set.addAll(outlines);
			outlines.clear();
			outlines.addAll(set);
		
		}
		
		output += String.join("", outlines);
		
		if(returnJSON) {
			totals.add(output.substring(0, output.length() -1) + "]");
		}
		else {
			totals.add(output + "\n}\n");
		}
		return totals;
	}
}