/*
 * trie.cpp
 *
 *  Created on: 2018-8-13
 *      Author: admin
 */

#include "stdinc.h"
#include <stdio.h>
#include <stdlib.h>
#include<queue>
#include<list>
#include<math.h>
#include "trie.h"
#include"EcoCAM.h"

using namespace std;

trie::trie(int numrules1, int binth1, pc_rule* rule1, int threshold1, int k1) {
	numrules = numrules1;
	binth = binth1;
	rule = rule1;
	k = k1; //0:SA, 1:DA
	threshold = (int) pow(2, threshold1);		//printf ("threshold: %d...\n",threshold);
	nodeSet = new nodeItem[MAXNODES + 1];
	root = 1;
	freelist = 2;
	pass = 1;
	max_depth = 0;
	Total_Rule_Size = 0;
	Total_Array_Size = 0;
	Leaf_Node_Count = 0;
	NonLeaf_Node_Count = 0;
	total_ficuts_memory_in_KB = 0;
	total_hs_memory_in_KB = 0;
	total_memory_in_KB = 0;

	for (int i = 1; i <= MAXNODES; i++)
		nodeSet[i].child = (int*) malloc(sizeof(int));

	nodeSet[root].isleaf = 0;
	nodeSet[root].nrules = numrules;

	for (int i = 0; i < MAXDIMENSIONS; i++) {
		nodeSet[root].field[i].low = 0;
		if (i < 2)
			nodeSet[root].field[i].high = 0xffffffff;
		else if (i == 4)
			nodeSet[root].field[i].high = 255;
		else
			nodeSet[root].field[i].high = 65535;
	}

	nodeSet[root].ruleid = (int*) calloc(numrules, sizeof(int));
	for (int i = 0; i < numrules; i++)
		nodeSet[root].ruleid[i] = i;

	nodeSet[root].ncuts = 0;
	nodeSet[root].layNo = 1;
	nodeSet[root].flag = 1;
	nodeSet[root].father = -1;

	nodeSet[root].blocksize = BLOCKSIZE;
	nodeSet[root].abs = nodeSet[root].nrules - nodeSet[root].blocksize;

	for (int i = 2; i < MAXNODES; i++)
		nodeSet[i].child[0] = i + 1;
	nodeSet[MAXNODES].child[0] = Null;

	if(k == 3)	// cutting with two dimensions (SA and DA)
		{
		createtires();
		}
	else		// cutting with one dimension (SA or DA)
		{
		createtrie();
		}

}

trie::nodeItem::nodeItem() {
	flag = layNo = father = id = nrules = isleaf = 0;
	rulelist = ruleid = child = NULL;
	ncuts = 0;

	blocksize = BLOCKSIZE;
	abs = -1;
}
trie::nodeItem::nodeItem(const trie::nodeItem &n) {
	flag = n.flag;
	layNo = n.layNo;
	father = n.father;
	id = n.id;
	nrules = n.nrules;
	isleaf = n.isleaf;
	ncuts = n.ncuts;
	rulelist = n.rulelist;

	blocksize = n.blocksize;
	abs = n.abs;

	ruleid = new int[nrules];
	for (int i = 0; i < nrules; i++)
		ruleid[i] = n.ruleid[i];
	child = new int[ncuts];
	for (unsigned int i = 0; i < ncuts; i++) {
		child[i] = n.child[i];
	}
}

trie::nodeItem & trie::nodeItem::operator=(const trie::nodeItem & n) {
	flag = n.flag;
	layNo = n.layNo;
	father = n.father;
	id = n.id;
	nrules = n.nrules;
	isleaf = n.isleaf;
	ncuts = n.ncuts;
	rulelist = n.rulelist;

	blocksize = n.blocksize;
	abs = n.abs;

	ruleid = new int[nrules];
	for (int i = 0; i < nrules; i++)
		ruleid[i] = n.ruleid[i];
	child = new int[ncuts];
	for (unsigned int i = 0; i < ncuts; i++) {
		child[i] = n.child[i];
	}
	return *this;

}

trie::trie(const trie& t) {
	binth = t.binth;
	pass = t.pass; // max trie level
	k = t.k; //dim. of small
	freelist = t.freelist; // first nodeItem on free list
	threshold = t.threshold;

	Total_Rule_Size = t.Total_Rule_Size; // number of rules stored
	Total_Array_Size = t.Total_Array_Size;
	Leaf_Node_Count = t.Leaf_Node_Count;
	NonLeaf_Node_Count = t.NonLeaf_Node_Count;
	total_ficuts_memory_in_KB = t.total_ficuts_memory_in_KB;
	total_hs_memory_in_KB = t.total_hs_memory_in_KB;
	total_memory_in_KB = t.total_memory_in_KB;

	max_depth = t.max_depth;
	numrules = t.numrules;
	rule = t.rule;
	root = t.root; // root of trie
	nodeSet = new nodeItem[MAXNODES + 1];

	for (int i = 0; i < MAXNODES + 1; i++)
		nodeSet[i] = t.nodeSet[i];

}


trie::nodeItem::~nodeItem() {
if (child!=NULL)delete child;
if (ruleid!=NULL)delete ruleid;
}

trie::~trie() {
	delete[] nodeSet;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  count_np_ficut
 *  Description:  judge if there is rule replication with one dimension cutting
 * =====================================================================================
 */
int trie::count_np_ficut(nodeItem *v) {
	int done = 0;
	int nump = 0;
	unsigned int lo, hi, r;
	int *nr;
	nr=(int *)malloc(sizeof(int));
	int sm=0;

//	*d = v->dim;

	if (v->field[k].high == v->field[k].low)
		nump = 1;
	else
		nump = 2;

	while (!done) {
		sm=0;
		nr = (int*)realloc(nr, nump*sizeof(int));
		for(int i=0; i<nump; i++)
			nr[i]=0;
		for (int j = 0; j < v->nrules; j++) {
			r = (v->field[k].high - v->field[k].low) / nump;
			lo = v->field[k].low;
			hi = lo + r;

			for (int i = 0; i < nump; i++) {
                if(rule[v->ruleid[j]].field[k].low >=lo && rule[v->ruleid[j]].field[k].low <=hi ||
                   rule[v->ruleid[j]].field[k].high>=lo && rule[v->ruleid[j]].field[k].high<=hi ||
                   rule[v->ruleid[j]].field[k].low <=lo && rule[v->ruleid[j]].field[k].high>=hi){
                   sm++;
                   nr[i]++;
                   }
				lo = hi + 1;
				hi = lo + r;
			}
		}

		//judge if there is rule replication
		if (sm == v->nrules && nump < MAXCUTS && (v->field[k].high - v->field[k].low) > threshold) {
			nump = nump * 2;
			if (nump == MAXCUTS) {			//further cuts
				int Nrules = 0;
				for (int j = 0; j < v->nrules; j++) {
					r = (v->field[k].high - v->field[k].low) / MAXCUTS;
					lo = v->field[k].low;
					hi = lo + r;

					for (int i = 0; i < MAXCUTS; i++) {
		                if(rule[v->ruleid[j]].field[k].low >=lo && rule[v->ruleid[j]].field[k].low <=hi ||
		                   rule[v->ruleid[j]].field[k].high>=lo && rule[v->ruleid[j]].field[k].high<=hi ||
		                   rule[v->ruleid[j]].field[k].low <=lo && rule[v->ruleid[j]].field[k].high>=hi){
		                	Nrules++;
		                   }
						lo = hi + 1;
						hi = lo + r;
					}
				}

				if (Nrules > v->nrules)
				{
					nump = nump/2;
					done = 1;
				}
			}
		}
		else
			done = 1;
	}
	return nump;
}

//cutting with one dimension (SA or DA) without rule replication
void trie::createtrie() {
	int v = 0;
	int np = 0;
	int nr;
	int empty;
	unsigned int r1, lo1, hi1;
	int u;

	qNode.push(root);

	while (!qNode.empty()) {
		v = qNode.front();
		qNode.pop();

		if (nodeSet[v].flag == 1) {
			np = count_np_ficut(&nodeSet[v]);
			if (np < MAXCUTS)
				nodeSet[v].flag = 2;
		}

		if (nodeSet[v].flag == 1) //Cuts stage
		{
			if (nodeSet[v].nrules <= binth || np == 1) {
				nodeSet[v].isleaf = 1;
				nodeSet[v].abs = abs(nr - nodeSet[v].blocksize);
				Total_Rule_Size += nodeSet[v].nrules;
				Leaf_Node_Count++;
				if (max_depth < (nodeSet[v].layNo + nodeSet[v].nrules))
					max_depth = nodeSet[v].layNo + nodeSet[v].nrules;
			} else {
				NonLeaf_Node_Count++;
				nodeSet[v].ncuts = np;
				nodeSet[v].child = (int *) realloc(nodeSet[v].child,
						nodeSet[v].ncuts * sizeof(int));

				Total_Array_Size += nodeSet[v].ncuts;

				r1 = (nodeSet[v].field[k].high - nodeSet[v].field[k].low)
						/ nodeSet[v].ncuts;
				lo1 = nodeSet[v].field[k].low;
				hi1 = lo1 + r1;

				for (unsigned int i = 0; i < nodeSet[v].ncuts; i++) {
					empty = 1;
					nr = 0;
					for (int j = 0; j < nodeSet[v].nrules; j++) {
						if (rule[nodeSet[v].ruleid[j]].field[k].low >= lo1
								&& rule[nodeSet[v].ruleid[j]].field[k].low
										<= hi1
								|| rule[nodeSet[v].ruleid[j]].field[k].high
										>= lo1
										&& rule[nodeSet[v].ruleid[j]].field[k].high
												<= hi1
								|| rule[nodeSet[v].ruleid[j]].field[k].low
										<= lo1
										&& rule[nodeSet[v].ruleid[j]].field[k].high
												>= hi1) {
							empty = 0;
							nr++;
						}
					}

					if (!empty) {
						nodeSet[v].child[i] = freelist;
						u = freelist;
						freelist++;
						nodeSet[u].father = v;
						nodeSet[u].id = u;
						nodeSet[u].nrules = nr;

						nodeSet[u].abs = abs(nr - nodeSet[u].blocksize);

						if ( nr <= binth) {
							nodeSet[v].isleaf = 1;
							nodeSet[u].isleaf = 1;
							Total_Rule_Size += nr;
							Leaf_Node_Count++;
							nodeSet[u].layNo = nodeSet[v].layNo + 1;

							if (max_depth < (nodeSet[u].layNo + nr))
								max_depth = nodeSet[v].layNo + nr;

						} else {
							nodeSet[u].isleaf = 0;
							nodeSet[u].layNo = nodeSet[v].layNo + 1;

							if (np < MAXCUTS)
								nodeSet[u].flag = 2;
							else
								nodeSet[u].flag = 1;

							if (pass < nodeSet[u].layNo)
								pass = nodeSet[u].layNo;
							qNode.push(u);
						}

						for (int t = 0; t < MAXDIMENSIONS; t++) {
							if (t != k) {
								nodeSet[u].field[t].low
										= nodeSet[v].field[t].low;
								nodeSet[u].field[t].high
										= nodeSet[v].field[t].high;
							} else {
								nodeSet[u].field[t].low = lo1;
								nodeSet[u].field[t].high = hi1;
							}
						}

						int s = 0;
						nodeSet[u].ruleid = (int *) calloc(nodeSet[v].nrules,
								sizeof(int));
						for (int j = 0; j < nodeSet[v].nrules; j++) {
							if (rule[nodeSet[v].ruleid[j]].field[k].low >= lo1
									&& rule[nodeSet[v].ruleid[j]].field[k].low
											<= hi1
									|| rule[nodeSet[v].ruleid[j]].field[k].high
											>= lo1
											&& rule[nodeSet[v].ruleid[j]].field[k].high
													<= hi1
									|| rule[nodeSet[v].ruleid[j]].field[k].low
											<= lo1
											&& rule[nodeSet[v].ruleid[j]].field[k].high
													>= hi1) {
								nodeSet[u].ruleid[s] = nodeSet[v].ruleid[j];
								s++;
							}
						}

					} else
						nodeSet[v].child[i] = Null;

					lo1 = hi1 + 1;
					hi1 = lo1 + r1;
				}

			}
		}
	}

}



/*
 * ===  FUNCTION  ======================================================================
 *         Name:  count_np_ficut
 *  Description:  judge if there is rule replication with two different dimensions cutting(SA and DA)
 * =====================================================================================
 */
int trie::count_np_ficut(nodeItem *v, int d) {
	int done = 0;
	int nump = 0;
	unsigned int lo, hi, r;
	int *nr;
	nr=(int *)malloc(sizeof(int));
	int sm=0;

	if (v->field[d].high == v->field[d].low)
		nump = 1;
	else
		nump = 2;

	while (!done) {
		sm=0;
		nr = (int*)realloc(nr, nump*sizeof(int));
		for(int i=0; i<nump; i++)
			nr[i]=0;
		for (int j = 0; j < v->nrules; j++) {
			r = (v->field[d].high - v->field[d].low) / nump;
			lo = v->field[d].low;
			hi = lo + r;

			for (int i = 0; i < nump; i++) {
                if(rule[v->ruleid[j]].field[d].low >=lo && rule[v->ruleid[j]].field[d].low <=hi ||
                   rule[v->ruleid[j]].field[d].high>=lo && rule[v->ruleid[j]].field[d].high<=hi ||
                   rule[v->ruleid[j]].field[d].low <=lo && rule[v->ruleid[j]].field[d].high>=hi){
                   sm++;
                   nr[i]++;
                   }
				lo = hi + 1;
				hi = lo + r;
			}
		}

		if (sm == v->nrules && nump < MAXCUTS && (v->field[d].high - v->field[d].low) > threshold) {
			nump = nump * 2;
			if (nump == MAXCUTS) {
				int Nrules = 0;
				for (int j = 0; j < v->nrules; j++) {
					r = (v->field[d].high - v->field[d].low) / MAXCUTS;
					lo = v->field[d].low;
					hi = lo + r;

					for (int i = 0; i < MAXCUTS; i++) {
		                if(rule[v->ruleid[j]].field[d].low >=lo && rule[v->ruleid[j]].field[d].low <=hi ||
		                   rule[v->ruleid[j]].field[d].high>=lo && rule[v->ruleid[j]].field[d].high<=hi ||
		                   rule[v->ruleid[j]].field[d].low <=lo && rule[v->ruleid[j]].field[d].high>=hi){
		                	Nrules++;
		                   }
						lo = hi + 1;
						hi = lo + r;
					}
				}

				if (Nrules > v->nrules)
				{
					nump = nump/2;
					done = 1;
				}
			}
		}
		else
			done = 1;
	}
	return nump;
}

//cutting with two dimensions (SA and DA)
void trie::createtires() {
	int v = 0;
	int np = 0;
	int nr;
	int empty;
	unsigned int r1, lo1, hi1;
	int u;
	int d;

	qNode.push(root);

	while (!qNode.empty()) {
		v = qNode.front();
		qNode.pop();

		if (nodeSet[v].flag == 1) {
			np = count_np_ficut(&nodeSet[v], (nodeSet[v].flag - 1));
			if (np < MAXCUTS)
				nodeSet[v].flag = 2;
		}

		if (nodeSet[v].flag == 1) //SA cutting stage
		{
			d = 0;
			if (nodeSet[v].nrules <= binth || np == 1) {
				nodeSet[v].isleaf = 1;
				nodeSet[v].abs = abs(nr - nodeSet[v].blocksize);
				Total_Rule_Size += nodeSet[v].nrules;
				Leaf_Node_Count++;
				if (max_depth < (nodeSet[v].layNo + nodeSet[v].nrules))
					max_depth = nodeSet[v].layNo + nodeSet[v].nrules;
			} else {
				NonLeaf_Node_Count++;
				nodeSet[v].ncuts = np;
				nodeSet[v].child = (int *) realloc(nodeSet[v].child,
						nodeSet[v].ncuts * sizeof(int));

				Total_Array_Size += nodeSet[v].ncuts;

				r1 = (nodeSet[v].field[d].high - nodeSet[v].field[d].low)
						/ nodeSet[v].ncuts;
				lo1 = nodeSet[v].field[d].low;
				hi1 = lo1 + r1;

				for (unsigned int i = 0; i < nodeSet[v].ncuts; i++) {
					empty = 1;
					nr = 0;
					for (int j = 0; j < nodeSet[v].nrules; j++) {
						if (rule[nodeSet[v].ruleid[j]].field[d].low >= lo1
								&& rule[nodeSet[v].ruleid[j]].field[d].low
										<= hi1
								|| rule[nodeSet[v].ruleid[j]].field[d].high
										>= lo1
										&& rule[nodeSet[v].ruleid[j]].field[d].high
												<= hi1
								|| rule[nodeSet[v].ruleid[j]].field[d].low
										<= lo1
										&& rule[nodeSet[v].ruleid[j]].field[d].high
												>= hi1) {
							empty = 0;
							nr++;
						}
					}

					if (!empty) {
						nodeSet[v].child[i] = freelist;
						u = freelist;
						freelist++;
						nodeSet[u].father = v;
						nodeSet[u].id = u;
						nodeSet[u].nrules = nr;

						nodeSet[u].abs = abs(nr - nodeSet[u].blocksize);
						//		printf("father: %d,node_id: %d ,rule: %d\n",nodeSet[u].father,nodeSet[u].id,nodeSet[u].nrules);

						if ( nr <= binth) {
							nodeSet[v].isleaf = 1;
							nodeSet[u].isleaf = 1;
							Total_Rule_Size += nr;
							Leaf_Node_Count++;
							nodeSet[u].layNo = nodeSet[v].layNo + 1;

							if (max_depth < (nodeSet[u].layNo + nr))
								max_depth = nodeSet[v].layNo + nr;

						} else {
							nodeSet[u].isleaf = 0;
							nodeSet[u].layNo = nodeSet[v].layNo + 1;

							if (np < MAXCUTS)
								nodeSet[u].flag = 2;
							else
								nodeSet[u].flag = 1;

							if (pass < nodeSet[u].layNo)
								pass = nodeSet[u].layNo;
							qNode.push(u);
						}

						for (int t = 0; t < MAXDIMENSIONS; t++) {
							if (t != d) {
								nodeSet[u].field[t].low
										= nodeSet[v].field[t].low;
								nodeSet[u].field[t].high
										= nodeSet[v].field[t].high;
							} else {
								nodeSet[u].field[t].low = lo1;
								nodeSet[u].field[t].high = hi1;
							}
						}
//						printf("level: %d, father: %d ,node_id: %d ,rule: %d, v: %d\n",nodeSet[u].layNo, nodeSet[u].father, nodeSet[u].id, nodeSet[u].nrules, nodeSet[u].v);
//						printf("level: %d , nrules: %d\n",nodeSet[u].layNo,nodeSet[u].nrules);
						int s = 0;
						nodeSet[u].ruleid = (int *) calloc(nodeSet[v].nrules,
								sizeof(int));
						for (int j = 0; j < nodeSet[v].nrules; j++) {
							if (rule[nodeSet[v].ruleid[j]].field[d].low >= lo1
									&& rule[nodeSet[v].ruleid[j]].field[d].low
											<= hi1
									|| rule[nodeSet[v].ruleid[j]].field[d].high
											>= lo1
											&& rule[nodeSet[v].ruleid[j]].field[d].high
													<= hi1
									|| rule[nodeSet[v].ruleid[j]].field[d].low
											<= lo1
											&& rule[nodeSet[v].ruleid[j]].field[d].high
													>= hi1) {
								nodeSet[u].ruleid[s] = nodeSet[v].ruleid[j];
								s++;
							}
						}

					} else
						nodeSet[v].child[i] = Null;

					lo1 = hi1 + 1;
					hi1 = lo1 + r1;
				}

			}
		}

		if (nodeSet[v].flag == 2)	//DA cutting stage
		{
			np = count_np_ficut(&nodeSet[v], (nodeSet[v].flag - 1));

			if (np < MAXCUTS)
				nodeSet[v].flag = 3;

			if (nodeSet[v].flag == 2)
			{
				d = 1;
				if (nodeSet[v].nrules <= binth || np == 1) {
					nodeSet[v].isleaf = 1;
					nodeSet[v].abs = abs(nr - nodeSet[v].blocksize);
					Total_Rule_Size += nodeSet[v].nrules;
					Leaf_Node_Count++;
					if (max_depth < (nodeSet[v].layNo + nodeSet[v].nrules))
						max_depth = nodeSet[v].layNo + nodeSet[v].nrules;
				} else {
					NonLeaf_Node_Count++;
					nodeSet[v].ncuts = np;
					nodeSet[v].child = (int *) realloc(nodeSet[v].child,
							nodeSet[v].ncuts * sizeof(int));

					Total_Array_Size += nodeSet[v].ncuts;

					r1 = (nodeSet[v].field[d].high - nodeSet[v].field[d].low)
							/ nodeSet[v].ncuts;
					lo1 = nodeSet[v].field[d].low;
					hi1 = lo1 + r1;

					for (unsigned int i = 0; i < nodeSet[v].ncuts; i++) {
						empty = 1;
						nr = 0;
						for (int j = 0; j < nodeSet[v].nrules; j++) {
							if (rule[nodeSet[v].ruleid[j]].field[d].low >= lo1
									&& rule[nodeSet[v].ruleid[j]].field[d].low
											<= hi1
									|| rule[nodeSet[v].ruleid[j]].field[d].high
											>= lo1
											&& rule[nodeSet[v].ruleid[j]].field[d].high
													<= hi1
									|| rule[nodeSet[v].ruleid[j]].field[d].low
											<= lo1
											&& rule[nodeSet[v].ruleid[j]].field[d].high
													>= hi1) {
								empty = 0;
								nr++;
							}
						}

						if (!empty) {
							nodeSet[v].child[i] = freelist;
							u = freelist;
							freelist++;
							nodeSet[u].father = v;
							nodeSet[u].id = u;
							nodeSet[u].nrules = nr;

							nodeSet[u].abs = abs(nr - nodeSet[u].blocksize);
							//		printf("father: %d,node_id: %d ,rule: %d\n",nodeSet[u].father,nodeSet[u].id,nodeSet[u].nrules);

							if ( nr <= binth) {
								nodeSet[v].isleaf = 1;
								nodeSet[u].isleaf = 1;
								Total_Rule_Size += nr;
								Leaf_Node_Count++;
								nodeSet[u].layNo = nodeSet[v].layNo + 1;

								if (max_depth < (nodeSet[u].layNo + nr))
									max_depth = nodeSet[v].layNo + nr;

							} else {
								nodeSet[u].isleaf = 0;
								nodeSet[u].layNo = nodeSet[v].layNo + 1;

								if (np < MAXCUTS)
									nodeSet[u].flag = 3;
								else
									nodeSet[u].flag = 2;

								if (pass < nodeSet[u].layNo)
									pass = nodeSet[u].layNo;
								qNode.push(u);
							}

							for (int t = 0; t < MAXDIMENSIONS; t++) {
								if (t != d) {
									nodeSet[u].field[t].low
											= nodeSet[v].field[t].low;
									nodeSet[u].field[t].high
											= nodeSet[v].field[t].high;
								} else {
									nodeSet[u].field[t].low = lo1;
									nodeSet[u].field[t].high = hi1;
								}
							}
//							printf("level: %d, father: %d ,node_id: %d ,rule: %d, v: %d\n",nodeSet[u].layNo, nodeSet[u].father, nodeSet[u].id, nodeSet[u].nrules, nodeSet[u].v);
	//						printf("level: %d , nrules: %d\n",nodeSet[u].layNo,nodeSet[u].nrules);
							int s = 0;
							nodeSet[u].ruleid = (int *) calloc(nodeSet[v].nrules,
									sizeof(int));
							for (int j = 0; j < nodeSet[v].nrules; j++) {
								if (rule[nodeSet[v].ruleid[j]].field[d].low >= lo1
										&& rule[nodeSet[v].ruleid[j]].field[d].low
												<= hi1
										|| rule[nodeSet[v].ruleid[j]].field[d].high
												>= lo1
												&& rule[nodeSet[v].ruleid[j]].field[d].high
														<= hi1
										|| rule[nodeSet[v].ruleid[j]].field[d].low
												<= lo1
												&& rule[nodeSet[v].ruleid[j]].field[d].high
														>= hi1) {
									nodeSet[u].ruleid[s] = nodeSet[v].ruleid[j];
									s++;
								}
							}

						} else
							nodeSet[v].child[i] = Null;

						lo1 = hi1 + 1;
						hi1 = lo1 + r1;
					}

				}
			}
		}
	}





}

bool trie::nodeItem::operator <(const trie::nodeItem b) const {
	if (abs != b.abs)
		return abs > b.abs;
	return layNo > b.layNo;
}


