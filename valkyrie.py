#!/usr/bin/env python
#-*-coding:utf-8-*-

#
# Copyright (C) 2020 Guillaume Celosia (guillaume.celosia@inria.fr) & Mathieu Cunche (mathieu.cunche@inria.fr)
#
# This file is subject to the terms and conditions defined in file 'LICENSE', which is part of this source code package.
#

from __future__ import division
from collections import OrderedDict
from distutils.util import strtobool
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from scipy.stats import kstest
from selectpoints import selectpoints #https://github.com/gaborgulyas/SelectPoints
from terminaltables import SingleTable
import argparse
import csv
import matplotlib.pyplot as plt
import os
import pyshark
import sys

def effect(s,c,close=True):
	if os.getenv('c','1')==0:
		return s
	else:
		return "\033[%dm%s%s" % (c,s,"\33[0m" if close else "")

def red(s,close=True):
	return effect(s,31,close)

def green(s,close=True):
	return effect(s,32,close)

def blue(s,close=True):
	return effect(s,34,close)

def bold(s,close=True):
	return effect(s,1,close)

def attribute_color(parameter,color_dict):
	color_lst=['aqua','aquamarine','bisque','black','blue','blueviolet','brown','burlywood','cadetblue','chartreuse','chocolate','coral','cornflowerblue','crimson','cyan','darkblue','darkcyan','darkgoldenrod','darkgray','darkgreen','darkgrey','darkkhaki','darkmagenta','darkolivegreen','darkorange','darkorchid','darkred','darksalmon','darkseagreen','darkslateblue','darkslategray','darkslategrey','darkturquoise','darkviolet','deeppink','deepskyblue','dimgray','dimgrey','dodgerblue','firebrick','forestgreen','fuchsia','gainsboro','gold','goldenrod','gray','green','greenyellow','grey','hotpink','indianred','indigo','khaki','lawngreen','lightblue','lightcoral','lightgray','lightgreen','lightgrey','lightpink','lightsalmon','lightseagreen','lightskyblue','lightslategray','lightslategrey','lightsteelblue','lime','limegreen','magenta','maroon','mediumaquamarine','mediumblue','mediumorchid','mediumpurple','mediumseagreen','mediumslateblue','mediumspringgreen','mediumturquoise','mediumvioletred','midnightblue','navajowhite','navy','olive','olivedrab','orange','orangered','orchid','palegoldenrod','palegreen','paleturquoise','palevioletred','peru','pink','plum','powderblue','purple','rebeccapurple','red','rosybrown','royalblue','saddlebrown','salmon','sandybrown','seagreen','sienna','silver','skyblue','slateblue','slategray','slategrey','springgreen','steelblue','tan','teal','thistle','tomato','turquoise','violet','wheat','yellow','yellowgreen']
	if parameter not in color_dict:
		if color_dict and color_lst.index(color_dict.values()[-1])+1<=len(color_lst):
			color_dict[parameter]=color_lst[color_lst.index(color_dict.values()[-1])+1]
			return
		color_dict[parameter]=color_lst[0]

def analyze_capture(capture,rule,parameters,increment,loop,ks_threshold,visualize_option):
	table_data=[['Time (since epoch)',parameters.split(',')[0],parameters.split(',')[1]]]
	change_lst=[]
	color_dict=OrderedDict()
	link_lst=[]
	reset_lst=[]
	ref=()
	warn=0

	for packet in capture:
		param=['null','null']
		for i in range(0,2): #search data associated with PARAM_0 and PARAM_1
			for j in packet.layers:
				if parameters.split(',')[i] in j._all_fields:
					param[i]=j._all_fields[parameters.split(',')[i]]

		if param[0]!='null' and param[1]!='null': #if PARAM_0 AND PARAM_1 are not NULL
			if not ref: #first packet to handle
				ref=(param[0],param[1],packet.frame_info.time_epoch)
				if rule=='SYNC_CNT_CHG':
					try:
						int(param[1])
					except:
						print '[ERROR] Parameter "'+parameters.split(',')[1]+'" is not a counter.'
						sys.exit(1)
					attribute_color(param[0],color_dict)
					#reset_lst.append((param[0],param[1],packet.frame_info.time_epoch))
			else:
				if param[0]!=ref[0] or param[1]!=ref[1]: #if PARAM_0 OR PARAM_1 change
					if param[0]!=ref[0] and param[1]!=ref[1]: #if PARAM_0 AND PARAM_1 change
						for i in range(0,2): #PARAM_0/PARAM_1 has taken the same value as before when change
							lst=[item for item in change_lst if item[i]==param[i]]
							if lst:
								table_data.extend(([lst[-1][2],lst[-1][0],lst[-1][1]],[packet.frame_info.time_epoch,param[0],param[1]],['','','']))
								print '[WARN] Parameter "'+parameters.split(',')[i]+'" has already taken this value @ '+packet.frame_info.time_epoch+'.'
								warn+=1

						if rule=='SYNC_CNT_CHG' and ref[1]!='null': #definition of the SYNC_CNT_CHG rule
							link_lst.append([[float(ref[2]),int(ref[1])],[float(packet.frame_info.time_epoch),int(param[1])]])
							reset_lst.append((param[0],param[1],packet.frame_info.time_epoch))
							attribute_color(param[0],color_dict)
							if cmp(int(param[1]),int(ref[1]))>0 and abs(int(param[1])-int(ref[1]))<=increment: #PARAM_1 is incremented
								table_data.extend(([ref[2],ref[0],ref[1]],[packet.frame_info.time_epoch,param[0],param[1]],['','','']))
								print '[WARN] Parameter "'+parameters.split(',')[1]+'" is incremented @ '+packet.frame_info.time_epoch+'.'
								warn+=1
							elif cmp(int(param[1]),int(ref[1]))<0 and abs(int(param[1])+loop-int(ref[1]))<=increment: #PARAM_1 has looped
								table_data.extend(([ref[2],ref[0],ref[1]],[packet.frame_info.time_epoch,param[0],param[1]],['','','']))
								print '[WARN] Parameter "'+parameters.split(',')[1]+'" has looped @ '+packet.frame_info.time_epoch+'.'
								warn+=1

					elif rule=='SYNC_ID_CHG' and param[0]==ref[0] and param[1]!=ref[1]: #PARAM_0 is not synchronously changed with PARAM_1
						table_data.extend(([ref[2],ref[0],ref[1]],[packet.frame_info.time_epoch,param[0],param[1]],['','','']))
						print '[WARN] Parameter "'+parameters.split(',')[0]+'" is not synchronously changed with parameter "'+parameters.split(',')[1]+'" @ '+packet.frame_info.time_epoch+'.'
						warn+=1
					elif param[0]!=ref[0] and param[1]==ref[1]: #PARAM_1 is not synchronously changed with PARAM_0
						table_data.extend(([ref[2],ref[0],ref[1]],[packet.frame_info.time_epoch,param[0],param[1]],['','','']))
						print '[WARN] Parameter "'+parameters.split(',')[1]+'" is not synchronously changed with parameter "'+parameters.split(',')[0]+'" @ '+packet.frame_info.time_epoch+'.'
						warn+=1
					change_lst.append((ref[0],ref[1],ref[2]))
				ref=(param[0],param[1],packet.frame_info.time_epoch)

	if ref: #if capture contains at least one packet
		if (change_lst and change_lst[-1]!=ref) or not change_lst:
			change_lst.append((ref[0],ref[1],ref[2]))

		if len(list(set([(item[0],item[1]) for item in change_lst])))==1: #PARAM_0 and PARAM_1 are static (i.e. do not change) over time
			table_data.extend(([change_lst[-1][2],change_lst[-1][0],change_lst[-1][1]],['','','']))
			print '[WARN] Parameters "'+parameters.split(',')[0]+'" and "'+parameters.split(',')[1]+'" are static (i.e. do not change) over time.'
			warn+=1
		else:
			for i in range(0,2): #PARAM_0/PARAM_1 is static (i.e. does not change) over time
				if len(list(set([item[i] for item in change_lst])))==1:
					table_data.extend(([change_lst[-1][2],change_lst[-1][0],change_lst[-1][1]],['','','']))
					print '[WARN] Parameter "'+parameters.split(',')[i]+'" is static (i.e. does not change) over time.'
					warn+=1

		if rule=='SYNC_CNT_CHG':
			if reset_lst:
				if reset_lst[-1]!=ref:
					reset_lst.append((ref[0],ref[1],ref[2]))
					attribute_color(ref[0],color_dict)
				if kstest([int(item[1]) for item in reset_lst],'uniform')[1]<ks_threshold: #submit values of the reset of the counter to the Kolmogorov-Smirnov statistical test
					#print '[DEBUG] Results of the Kolmogorov-Smirnov test: (statistic='+str(kstest([int(item[1]) for item in reset_lst],'uniform')[0])+', pvalue='+str(kstest([int(item[1]) for item in reset_lst],'uniform')[1])+')'
					print '[WARN] Parameter "'+parameters.split(',')[1]+'" is non-uniformly distributed (i.e. the reset of the counter is not random).'
					warn+=1

		if visualize_option: #if option enabled, visualize results in a SingleTable (and in a scatter plot for the SYNC_CNT_CHG rule)
			if len(table_data)>1:
				table_data.pop()
				print '\n'+SingleTable(table_data).table
			if rule=='SYNC_CNT_CHG':
				ax=plt.figure().add_subplot(1,1,1)
				for link in link_lst:
					selectpoints(ax,link,radius=0.6,ec='r',lw=2,ls='-',a=1,fill=False)
				plt.title(parameters.split(',')[1]+' wrt. time (since epoch)')
				plt.xlabel('Time (since epoch)')
				plt.ylabel(parameters.split(',')[1])
				plt.scatter([float(item[2]) for item in change_lst],[int(item[1]) for item in change_lst],color=[color_dict[item[0]] for item in change_lst],marker='o',edgecolors='black')
				legend=[Line2D([0],[0],color='white',marker='o',label='Data',markerfacecolor='white',markeredgecolor='black',markeredgewidth=1.1,markersize=6)]
				if link_lst:
					legend.append(Patch(facecolor='white',edgecolor='red',linewidth=1.6,label='Link'))
				plt.legend(handles=legend,loc='best')
				plt.show()

		if warn!=0:
			print bold(red('\n'+'The analysis raised '+str(warn)+' warning(s). Please correct them.'))
		else:
			print bold(green('The analysis raised no warning. Very privacy \o/'))
	else:
		print '[ERROR] No packets to analyze.'
		sys.exit(1)

def check_args(args,parser):
	if args.capture_file:
		try: #check the existence of the capture file
			capture=pyshark.FileCapture(args.capture_file)
		except:
			print '[ERROR] File "'+args.capture_file+'" is not found.'
			sys.exit(1)

		if args.rule and args.parameters: #run Valkyrie with only one rule
			if len(filter(None,args.parameters.split(',')))!=2: #check the format for PARAM_0 and PARAM_1
				print '[ERROR] Parameters must be formatted as "PARAM_0,PARAM_1".'
				sys.exit(1)
			if args.rule=='SYNC_ID_CHG' or args.rule=='SYNC_CNT_CHG': #check if the rule is implemented
				capture._display_filter=args.frame
				analyze_capture(capture,args.rule,args.parameters,args.increment,args.loop,args.ksthreshold,args.visualize)
			else:
				print '[ERROR] A correct rule (SYNC_ID_CHG / SYNC_CNT_CHG) must be provided for the capture analysis.'
				sys.exit(1)

		elif args.rule_file: #run Valkyrie with a file of rules
			first_rule=True
			try:
				rf=open(args.rule_file,'r')
			except:
				print '[ERROR] File "'+args.rule_file+'" is not found.'
				sys.exit(1)
			try:
				rf_reader=csv.reader(rf,delimiter=';')
				headers=next(rf_reader)
			except:
				print '[ERROR] File "'+args.rule_file+'" is not properly formatted.'
				sys.exit(1)
			for rule in rf_reader:
				if first_rule:
					print bold(blue('[RULE] '+';'.join(rule)))
					first_rule=False
				else:
					print bold(blue('\n[RULE] '+';'.join(rule)))
				if len(rule)==7:
					if not (rule[0]=='SYNC_ID_CHG' or rule[0]=='SYNC_CNT_CHG'): #check if the rule is implemented
						print '[ERROR] A correct rule (SYNC_ID_CHG / SYNC_CNT_CHG) must be provided for the capture analysis.'
						sys.exit(1)
					else:
						if len(filter(None,rule[2].split(',')))!=2: #check the format for PARAM_0 and PARAM_1
							print '[ERROR] Parameters must be formatted as "PARAM_0,PARAM_1".'
							sys.exit(1)
						else:
							capture._display_filter=rule[1]
							try:
								analyze_capture(capture,rule[0],rule[2],int(rule[3]),int(rule[4]),float(rule[5]),bool(strtobool(rule[6])))
							except:
								print '[ERROR] Rule is not properly formatted.'
								sys.exit(1)
				else:
					print '[ERROR] Rule is not properly formatted.'
					sys.exit(1)
			rf.close()
		else:
			parser.print_help()
	else:
		parser.print_help()

def main():
	parser=argparse.ArgumentParser()
	parser.add_argument('-c','--capture_file',action='store',type=str,default=None,help='Capture file to analyze',metavar='CAPTURE_FILE')
	parser.add_argument('-R','--rule_file',action='store',type=str,default=None,help='Rule file to analyze the capture file',metavar='RULE_FILE')
	parser.add_argument('-r','--rule',action='store',type=str,default=None,help='Rule to use for the analysis',metavar='SYNC_ID_CHG / SYNC_CNT_CHG')
	parser.add_argument('-f','--frame',action='store',type=str,default='frame',help='Type of frame to analyze (default = frame (= all frames))',metavar='FRAME_TYPE')
	parser.add_argument('-p','--parameters',action='store',type=str,default=None,help='Parameters to use for the analysis',metavar='PARAM_0,PARAM_1')
	parser.add_argument('-i','--increment',action='store',type=int,default=1,help='Increment value to use for the counter analysis (default = 1)',metavar='INCREMENT_INT')
	parser.add_argument('-l','--loop',action='store',type=int,default=1,help='Maximum number of values the counter can take before looping (default = 1)',metavar='LOOP_INT')
	parser.add_argument('-k','--ksthreshold',action='store',type=float,default=0.01,help='Threshold to use for the Kolmogorov-Smirnov statistical test (default = 0.01)',metavar='KSTHRESHOLD_FLOAT')
	parser.add_argument('-v','--visualize',action='store_true',help='Visualize results of the analysis')

	if len(sys.argv[1:])>0: #if at least one argument is provided
		check_args(parser.parse_args(sys.argv[1:]),parser)
	else:
		parser.print_help()

if __name__=="__main__":
	try:
		main()
	except KeyboardInterrupt,SystemExit:
		sys.exit(1)

	sys.exit(0)