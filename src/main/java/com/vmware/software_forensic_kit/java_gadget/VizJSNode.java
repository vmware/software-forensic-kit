/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget;

public class VizJSNode{
	public String label = "";
	public int id;
	public String color = "";
	public String title = "";
	public VizJSNode(String label, int id, String color, String title) {
		this.label = label;
		this.id = id;
		this.color = color;
		this.title = title;
	}
	public String toString() {
		
		String output = String.format("{\"label\":\"%s\", \"id\":%d", label, id);
		if(color != null)
			output += String.format(", \"color\":\"%s\"", color);
		if(title != null)
			output += String.format(", \"title\":\"%s\"",  title);
		output += "}";
		return output;
		
	}
}