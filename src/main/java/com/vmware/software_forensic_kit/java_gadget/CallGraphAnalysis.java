/***************************************************
 * Copyright 2019 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 ***************************************************/
package com.vmware.software_forensic_kit.java_gadget;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.vmware.software_forensic_kit.java_gadget.local.LocalCalls;

public class CallGraphAnalysis{
	
	
	private String jarFile;
	private HashMap<String, String> optionMap;
	private HashMap<String, ArrayList<String>> cgMap;
	private HashMap<String, ArrayList<String>> reverse_cgMap;
	private ArrayList<String> discoveredFuncs;
	private int maxDepth = 8;
	private boolean removeDuplicates = false;
	private String removeFromStart;
	
	public CallGraphAnalysis(String jarFile, HashMap<String, String> optionMap) {
		this.jarFile = jarFile;
		this.optionMap = optionMap;
		
	}
	public void run() {
		
		String funcName = optionMap.get("searchFunction");
		
		String newfuncName = funcName.replaceAll("\\*", ".+");

		reverse_cgMap = new HashMap<String, ArrayList<String>>();
		createMap();
		//fixMap();
		Pattern regex = null;
		try{
			regex = Pattern.compile(newfuncName);
		}
		catch(PatternSyntaxException e) {
			
		}
		ArrayList<String> newfuncNames = new ArrayList<String>();
		for (String key : reverse_cgMap.keySet()) {
			if(newfuncNames.contains(key) == false && ((regex != null && regex.matcher((CharSequence)key).find()) || key.contains(newfuncName))){
				newfuncNames.add(key);
			
			}
		}
		HashMap<String, Object> reverseFilterMap = filterAndFindMap(newfuncNames, 0,  new ArrayList<String>());
		discoveredFuncs = newfuncNames;
		
		if(discoveredFuncs.size() == 0) {
			//System.out.println("Function Name Not Found");
			//System.exit(0);
		}	
		this.parseOptionsAndExit(reverseFilterMap);
	}
	

	public HashMap<String, Object> filterAndFindMap(ArrayList<String> funcNames, int depth, ArrayList<String> itemsFound) {

		HashMap<String, Object> mapped = new HashMap<String, Object> ();
		if(funcNames == null || depth > 25 )
			return mapped;
		
		depth += 1;
		for(String funcName : funcNames) {
			
				
			//System.out.println(funcName + " " + Integer.toString(depth));
				ArrayList<String> temp = (ArrayList<String>)itemsFound.clone();
				
				if(!itemsFound.contains(funcName)) {
					//System.out.println(funcName);
					temp.add(funcName);
					String tempFuncName = funcName;
					if(funcName.substring(funcName.indexOf(":") + 1).indexOf(":") > -1) {
						
						tempFuncName = tempFuncName.substring(tempFuncName.indexOf(":") + 1);
					}
					
					mapped.put(funcName, filterAndFindMap(reverse_cgMap.get(tempFuncName), depth, temp));
				}
			
		}
		
		return mapped;
	}
	

	public void createMap() {
		
		try {
		
			BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(jarFile)));
	
			String line = reader.readLine();
			cgMap = new HashMap<String, ArrayList<String>>();

			while (line != null)   {
			  if(line.startsWith("M:")) {
				  String [] parts = line.split("\\s+");
				  String key = parts[0].substring(2);
				  String value = parts[1].substring(3).replaceAll("[\\t\\n\\r]+", "");
				  if(!cgMap.containsKey(key)) 
					  cgMap.put(key, new ArrayList<String>());
				  cgMap.get(key).add(value);
				  if(!reverse_cgMap.containsKey(value))
					  reverse_cgMap.put(value, new ArrayList<String>());
				  reverse_cgMap.get(value).add(key);
			  }	
			  
			  line = reader.readLine();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private CallGraphNode createSearch(CallGraphNode node, HashMap<String, Object> mapped) {
		
		CallGraphNode newNode;
		
		for (String key : mapped.keySet()) {
			newNode = new CallGraphNode(key);
			newNode = createSearch(newNode, (HashMap<String, Object>)mapped.get(key));
			node.addChild(newNode);
		}
		return node;

	}
	
	private void parseOptionsAndExit(HashMap<String, Object> reverseFilterMap) {
		
		if(optionMap.containsKey("depth")) {
			maxDepth = Integer.parseInt(optionMap.get("depth"));
		}
		if(optionMap.containsKey("removePrefix")) {
			removeFromStart = optionMap.get("removePrefix");
		}
		if(optionMap.containsKey("removeDuplicates")) {
			removeDuplicates = Boolean.getBoolean(optionMap.get("removeDuplicates"));
		}
		
		ArrayList<String> valList;
		for (String funcName : discoveredFuncs) {
			
			CallGraphNode newNode = new CallGraphNode(funcName);
			newNode = createSearch(newNode, reverseFilterMap);
			//newNode = startSearch(newNode, 1);
			if(optionMap.containsKey("prettyPrint")) {
				newNode.prettyPrint(maxDepth, removeFromStart, removeDuplicates);
			}
			else if(optionMap.containsKey("justPrint")) {
				newNode.justPrint(maxDepth, removeFromStart, removeDuplicates);
			}
			else if(optionMap.containsKey("graphViz")) {
				valList = newNode.htmlandgraphviz(false, maxDepth, removeFromStart, removeDuplicates);
				System.out.println(String.join("",valList));
			}
			else if(optionMap.containsKey("graphVizM")) {
				valList = newNode.htmlandgraphvizMultiple(false, maxDepth, removeFromStart, removeDuplicates);
				System.out.println(String.join("",valList));
			}
			else if(optionMap.containsKey("html")) {
				valList = newNode.htmlandgraphviz(true, maxDepth, removeFromStart, removeDuplicates);
				//outToFile(newNode.cleanData(removeFromStart), valList);
				if(optionMap.containsKey("callgraphFile") == false) {
					outToFile(new File(this.jarFile).getName(), valList);
				}
				else {
					outToFile(funcName, valList);
				}
			}
			else {
				//htmlM
				valList = newNode.htmlandgraphvizMultiple(true, maxDepth, removeFromStart, removeDuplicates);
				//outToFile(newNode.cleanData(removeFromStart), valList);
				if(optionMap.containsKey("callgraphFile") == false) {
					outToFile(new File(this.jarFile).getName(), valList);
				}
				else {
					outToFile(funcName, valList);
				}
				
			}
		}
	}
	public ArrayList<String> findAndRemoveType(String dataVal) {
		HashMap<String, String> colorMap = new HashMap<String, String>();
		
		colorMap.put("public", "green");
		colorMap.put("private",  "red");
		colorMap.put("protected", "orange");
		colorMap.put("synchronized", "blue");
		colorMap.put("final",  "grey");
		
		String color = null;
		boolean found = true;
		ArrayList<String> titles = new ArrayList<String>();
		
		while (found == true) {
			found = false;
			for(String key: colorMap.keySet()) {
				if(dataVal.startsWith(String.format("%s:", key))) {
					dataVal = dataVal.substring(key.length() + 1);
					color = colorMap.get(key);
					titles.add(key);
					found = true;
				}
			}
		}
		return new ArrayList(Arrays.asList(dataVal, color, String.join(" ",  titles)));
	}
	public ArrayList getNodeId(ArrayList<VizJSNode> nodes, String dataVal) {
		int id = -1;
		ArrayList<String> stuff = findAndRemoveType(dataVal);
		for(VizJSNode node: nodes) {
			if(node.label.equals(dataVal)) {
				id = node.id;
			}
		}
		if(id == -1) {
			if(nodes.size() > 0) 
				id = nodes.get(nodes.size() -1).id + 1;
			
			else
				id = 1;
			
			VizJSNode obj = new VizJSNode(dataVal, id, null, null);
			if(stuff.get(1) != null )
				obj.color = stuff.get(1).toString();
			if(stuff.get(2) != null && stuff.get(2).toString().length() > 0)
				obj.title = stuff.get(2);
			nodes.add(obj);
		}
		return new ArrayList(Arrays.asList(id, nodes));
	}

	private void outToFile(String funcName, ArrayList<String> dataList) {
		int i = 0;
		ArrayList<VizJSNode> nodes = new ArrayList<VizJSNode>();
		ArrayList<String> edges = new ArrayList<String>();
		List<basicJSON> dataArray;
		ArrayList toNodeData;
		ArrayList fromNodeData;
		String line = "";
		for (String data : dataList) {
			dataArray =  new Gson().fromJson(data, new TypeToken<ArrayList<basicJSON>>() {}.getType() );
			i += 1;
			for(basicJSON bJSON  : dataArray) {
				
				toNodeData = getNodeId(nodes, bJSON.to);
				nodes = (ArrayList<VizJSNode>)toNodeData.get(1);
				fromNodeData = getNodeId(nodes, bJSON.from);
				nodes = (ArrayList<VizJSNode>)fromNodeData.get(1);
				line = String.format("{\"from\":%d, \"to\":%d}", fromNodeData.get(0), toNodeData.get(0));
				if(edges.contains(line) == false) {
					edges.add(line);
				}
			}
		}
		
		String out = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\n\n" +
				"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n\n" +
		"<html>\n" +
		"<head>\n" +
		"\n\n" +
		"<title>Software_Forensic_Kit CallGraph: %s</title>\n" +
		"<script type=\"text/javascript\" src=\"https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js\"></script>\n" +
		"<link href=\"https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css\" rel=\"stylesheet\" type=\"text/css\">\n" +
		"\n"+
		"</head>\n" +
		"<body>\n" +
		"<div id=\"viscontainer\">\n" +
		"<div id=\"divcanvas\" class=\"vis-network\" tabindex=\"900\" style=\"resize: both; overflow:auto; border: 2px solid; position: relative; overflow: hidden; touch-action: pan-y; user-select: none; -webkit-user-drag: none; -webkit-tap-highlight-color: rgba(0, 0, 0, 0); width: 100%%; height: 100%%;\">\n" +
		"<canvas id=\"viscanvas\" min-height=\"900px\" style=\"min-width:1500px; width:100%%; height:100%%;position: relative; touch-action: none; user-select: none; -webkit-user-drag: none; -webkit-tap-highlight-color: rgba(0, 0, 0, 0); \">\n" +
		"</canvas></div></div>\n" +
		"<script>\n" +
		"var nodes = new vis.DataSet(%s);\n\n"+
		"var edges = new vis.DataSet(%s)\n\n\n" +
		"var container = document.getElementById('viscontainer');\n" +
		"var data = {nodes: nodes, edges: edges}; \n" +
		"var options = {\n" +
		"	height: '100%%',\n" +
		"	width: '100%%',\n" +
		"	layout: {\n" +
		"		hierarchical: { \n" +
		"			direction: \"UD\",\n" +
		"			sortMethod: \"directed\",\n" +
		"			nodeSpacing: 500\n" +
		"		}\n" +
		"	},\n" +
		"	interaction: {dragNodes :true},\n" +
		"	physics: {\n" +
		"		enabled: false\n" +
		"	},\n" +
		"	configure: {\n" +
		"	  filter: function (option, path) {\n" +
		"		  if (path.indexOf('hierarchical') !== -1) {\n" +
		"			  return true;\n" +
		"		  }\n" +
		"		  return false;\n" +
		"	  },\n" +
		"	  showButton:false\n" +
		"	}\n" +
		"};\n" +
		"var network = new vis.Network(container, data, options);\n\n" +
		"document.addEventListener('DOMContentLoaded', function(){\n" +
		"\n" +
		"document.getElementsByTagName(\"canvas\")[0].style.minHeight = \"450px\";\n" +
		"document.getElementsByClassName(\"vis-network\")[0].style.minHeight = \"450px\";\n" +
		"\n" +
		"}, false);\n" +
		"\n" +
		"</script>\n" +
		"</body>\n" +
		"</html>";
		String path;
		try {
			path = LocalCalls.getJarPath();
			String sep = System.getProperty("file.separator");
			funcName= funcName.replace("(", "_");
			funcName = funcName.replace(")", "_");
			funcName = funcName.replace(":", "_");
			System.out.println(String.format("OUTFILE:[%s]",  path + sep + "files" + sep + "output" + sep + funcName + ".html"));
			BufferedWriter writer = new BufferedWriter(new FileWriter(path + sep + "files" + sep + "output" + sep + funcName + ".html"));
			String outStr = String.format(out, funcName, Arrays.toString(nodes.toArray()), Arrays.toString(edges.toArray()));
			writer.write(outStr);
			writer.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	class basicJSON{
		public String to;
		public String from;
		public basicJSON(String to, String from) {
			this.to = to;
			this.from = from;
		}
		public String toString() {
			
			return String.format("{\"from\":\"%s\", \"to\":\"%s\"", from, to);
		
		}
	}

}