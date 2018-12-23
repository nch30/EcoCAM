/*
 * tre.h
 *
 *  Created on: 2018-8-13
 *      Author: admin
 */

#ifndef TRE_H_
#define TRE_H_

#include<stdio.h>
#include<stdlib.h>
#include<queue>
#include"EcoCAM.h"
using namespace std;

class trie {
public:
	struct nodeItem {
		bool isleaf;
		int *rulelist;
		int nrules;
		range field[MAXDIMENSIONS];
		int *ruleid;
		unsigned int ncuts;
		int id;
		int father;
		int* child;
		int layNo; //level
		int flag; //Cut or Not

		int blocksize;
		int abs;

		nodeItem();
		nodeItem(const nodeItem& n);
		~nodeItem();
		bool operator<(const nodeItem  b)const ;
		nodeItem &operator=(const nodeItem & b);
	};

public:

	int binth;
	int pass; // max trie level
	int k; //dim. of small
	int freelist; // first nodeItem on free list
	unsigned int threshold;

	int Total_Rule_Size; // number of rules stored
	int Total_Array_Size;
	int Leaf_Node_Count;
	int NonLeaf_Node_Count;
	float total_ficuts_memory_in_KB;
	float total_hs_memory_in_KB;
	float total_memory_in_KB;

	int max_depth;
	int numrules;
	pc_rule *rule;
	int root; // root of trie
	nodeItem *nodeSet; // base of array of NodeItems

public:
	queue<int> qNode; //queue for node
	trie(int, int, pc_rule*, int, int);
	int count_np_ficut(nodeItem*);
	void createtrie();
	int count_np_ficut(nodeItem*, int);
	void createtires();

	trie(const trie &t);
	~trie();
};

#endif /* TRE_H_ */
