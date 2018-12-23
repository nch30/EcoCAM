/*
 * CountTree.h
 *
 *  Created on: 2018-8-12
 *      Author: admin
 */

#ifndef COUNTTREE_H_
#define COUNTTREE_H_

#define MAXDIMENSIONS 5
#define MAXBUCKETS 40
#define MAXNODES 500000
#define MAXCUTS  16
#define PTR_SIZE 4
#define HEADER_SIZE 4
#define LEAF_NODE_SIZE 4
#define TREE_NODE_SIZE 8
#define BLOCKSIZE 128

class range {
public:
	unsigned low;
	unsigned high;
};

class pc_rule {
public:
	range field[MAXDIMENSIONS];
	bool isDone;
	bool isGeneral;
    int isCovered;
	int id;
};

class field_length {
public:
	unsigned length[5];
	int size[5];
	int flag_smallest[4];
};

class pc_entry {
public:
	range field[2];
	//int *ruleid;
	int size;
};




#endif /* COUNTTREE_H_ */
