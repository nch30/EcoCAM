//============================================================================
// Name        : EcoCAM.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<math.h>
#include<list>
#include"EcoCAM.h"
#include "common.h"
#include "stdinc.h"
#include <sys/time.h>
#include"trie.h"
#include "string.h"

using namespace std;

struct timeval	gStartTime,gEndTime;

FILE *fpr;           // ruleset file
int bucketSize = 2;   // leaf threashold
int threshold = 24;   // Assume T_SA=T_DA=threshold



/*
 * ===  FUNCTION  ======================================================================
 *         Name:  loadrule
 *  Description:  load rules from file
 * =====================================================================================
 */
int loadrule(FILE *fp,pc_rule *rule)
{
   int tmp;
   unsigned sip1,sip2,sip3,sip4,smask;
   unsigned dip1,dip2,dip3,dip4,dmask;
   unsigned sport1,sport2;
   unsigned dport1,dport2;
   unsigned protocal,protocol_mask;
   unsigned trace,trace_mask;
   int number_rule=0; //number of rules

   while(1){
//      if(fscanf(fp,"@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\n", &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &rule[number_rule].field[2].low, &rule[number_rule].field[2].high, &rule[number_rule].field[3].low, &rule[number_rule].field[3].high,&protocal, &protocol_mask)!= 16) break;

	      if(fscanf(fp,"@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\t%x/%x\n",
                &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &rule[number_rule].field[2].low, &rule[number_rule].field[2].high,
                &rule[number_rule].field[3].low, &rule[number_rule].field[3].high,&protocal, &protocol_mask, &trace, &trace_mask)!= 18) break;


   if(smask == 0){
      rule[number_rule].field[0].low = 0;
      rule[number_rule].field[0].high = 0xFFFFFFFF;
    }else if(smask > 0 && smask <= 8){
      tmp = sip1<<24;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1<<(32-smask)) - 1;
    }else if(smask > 8 && smask <= 16){
      tmp = sip1<<24; tmp += sip2<<16;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1<<(32-smask)) - 1;
    }else if(smask > 16 && smask <= 24){
      tmp = sip1<<24; tmp += sip2<<16; tmp +=sip3<<8;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1<<(32-smask)) - 1;
    }else if(smask > 24 && smask <= 32){
      tmp = sip1<<24; tmp += sip2<<16; tmp += sip3<<8; tmp += sip4;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1<<(32-smask)) - 1;
    }else{
      printf("Src IP length exceeds 32\n");
      return 0;
    }
    if(dmask == 0){
      rule[number_rule].field[1].low = 0;
      rule[number_rule].field[1].high = 0xFFFFFFFF;
    }else if(dmask > 0 && dmask <= 8){
      tmp = dip1<<24;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1<<(32-dmask)) - 1;
    }else if(dmask > 8 && dmask <= 16){
      tmp = dip1<<24; tmp +=dip2<<16;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1<<(32-dmask)) - 1;
    }else if(dmask > 16 && dmask <= 24){
      tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1<<(32-dmask)) - 1;
    }else if(dmask > 24 && dmask <= 32){
      tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8; tmp +=dip4;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1<<(32-dmask)) - 1;
    }else{
      printf("Dest IP length exceeds 32\n");
      return 0;
    }
    if(protocol_mask == 0xFF){
      rule[number_rule].field[4].low = protocal;
      rule[number_rule].field[4].high = protocal;
    }else if(protocol_mask== 0){
      rule[number_rule].field[4].low = 0;
      rule[number_rule].field[4].high = 0xFF;
    }else{
      printf("Protocol mask error\n");
      return 0;
    }

   number_rule++;
   }

   /*
   printf("the number of rules = %d\n", number_rule);
     for(int i=0;i<number_rule;i++){
      printf("%u: %u:%u %u:%u %u:%u %u:%u %u:%u\n", i,
        rule[i].field[0].low, rule[i].field[0].high,
        rule[i].field[1].low, rule[i].field[1].high,
        rule[i].field[2].low, rule[i].field[2].high,
        rule[i].field[3].low, rule[i].field[3].high,
        rule[i].field[4].low, rule[i].field[4].high);}
   */

  return number_rule;
}


void parseargs(int argc, char *argv[])
{
  int	c;
  bool	ok = 1;
  while ((c = getopt(argc, argv, "b:r:t:h")) != -1){
    switch (c) {
	case 'b':
	  bucketSize = atoi(optarg);
	  break;
	case 't':
	  threshold = atoi(optarg);
          break;
	case 'r':
	  fpr = fopen(optarg, "r");
          break;
	case 'h':
	  printf("mail me: chonghui_ning@pku.edu.cn\n");
	  exit(1);
	  break;
	default:
	  ok = 0;
        }
     }

  if(bucketSize <= 0 || bucketSize > MAXBUCKETS){
    printf("bucketSize should be greater than 0 and less than %d\n", MAXBUCKETS);
    ok = 0;
     }
  if(threshold < 0 || threshold > 32){
    printf("threshold should be greater than 0 and less than 32\n");
    ok = 0;
     }
  if(fpr == NULL){
    printf("can't open ruleset file\n");
    ok = 0;
     }
  if (!ok || optind < argc){
    fprintf (stderr, "EcoCAM [-b bucketSize][-t threshold(assume T_SA=T_DA)][-r ruleset]\n");
    fprintf (stderr, "Type \"EcoCAM -h\" for help\n");
    exit(1);
     }

   printf("************EcoCAM: version 1.0******************\n");
   printf("Bucket Size =  %d\n", bucketSize);
   printf("Threshold = %d,%d\n", threshold,threshold);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  dump_rule
 *  Description:  dump rules or rule set, for testing
 * =====================================================================================
 */
void dump_rule(pc_rule *rule, int rule_id)
{
	int	 i;
	pc_rule	 *p = &rule[rule_id];
	range    r;

	printf("rule[%d]:\t", rule_id);

	// dump SIP & DIP
	for (i = 0; i < 2; i++) {
		r = p->field[i];
		if (r.low == r.high)
			dump_ip(r.low);
		else if (r.low == 0 && r.high == 0xffffffff)
			printf("*");
		else {
			dump_ip(r.low);
			printf("/%d", log2(r.high-r.low+1));
		}
		printf(",\t");
	}

	// dump SP & DP
	for (i = 2; i < 4; i++) {
		r = p->field[i];
		if (r.low == r.high)
			printf("%x", r.low);
		else if (r.low == 0 && r.high == 0xffff)
			printf("*");
		else {
			printf("[%x-%x]", r.low, r.high);
		}
		printf(",  ");
	}

	// dump proto
	r = p->field[4];
	if (r.low == r.high)
		printf("%d", r.low);
	else if (r.low == 0 && r.high == 0xff)
		printf("*");
	else
		printf("[%d-%d]", r.low, r.high);

	printf("\n");
}

void dump_ruleset(pc_rule *rule, int num)
{
  for (int i = 0; i < num; i++)
      dump_rule(rule,i);
  printf("\n");
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  count_length
 *  Description:  record length of field and correponding size
 * =====================================================================================
 */
void count_length(int number_rule,pc_rule *rule,field_length *field_length_ruleset)
{
   unsigned temp_size=0;
   unsigned temp_value=0;
   //unsigned temp0=0;

   for(int i=0;i<number_rule;i++)
      {
       for(int j=0;j<5;j++)  //record field length in field_length_ruleset[i]
          {
          field_length_ruleset[i].length[j]=rule[i].field[j].high-rule[i].field[j].low;
          if(field_length_ruleset[i].length[j]==0xffffffff)
             field_length_ruleset[i].size[j]=32; //for address *
          else
             {
             temp_size=0;
             temp_value=field_length_ruleset[i].length[j]+1;
             while((temp_value=temp_value/2)!=0)
                temp_size++;
             //for port number
             if((field_length_ruleset[i].length[j]+1 - pow(2,temp_size))!=0)
               temp_size++;

             field_length_ruleset[i].size[j]=temp_size;
             }
          }
      }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  partition_v3 (version3)
 *  Description:  partition ruleset into big_subsets SA_subsets DA_subsets small_subsets based on address field(2 dim.)
 * =====================================================================================
 */
void partition_v3(pc_rule *rule, pc_rule* subset[4], int num_subset[4],
		int number_rule, field_length *field_length_ruleset,
		int threshold_value[2]) {
	int num_small_tmp[number_rule];
	for (int i = 0; i < number_rule; i++) {
		num_small_tmp[i] = 0;
		for (int k = 0; k < 2; k++)
			if (field_length_ruleset[i].size[k] <= threshold_value[k])
				num_small_tmp[i]++;
	}

	int count_big = 0;
	for (int i = 0; i < number_rule; i++)
		if (num_small_tmp[i] == 0)
			subset[0][count_big++] = rule[i];
	num_subset[0] = count_big;

	int count_sa = 0;
	int count_da = 0;
	int count_small = 0;
	for (int i = 0; i < number_rule; i++) {
		if ((num_small_tmp[i] == 1) && (field_length_ruleset[i].size[0]
				<= threshold_value[0]))
			subset[1][count_sa++] = rule[i];
		if ((num_small_tmp[i] == 1) && (field_length_ruleset[i].size[1]
				<= threshold_value[1]))
			subset[2][count_da++] = rule[i];

		if (num_small_tmp[i] == 2) {		//}��С��threshold
			subset[3][count_small++] = rule[i];
		}
	}

	num_subset[1] = count_sa;
	num_subset[2] = count_da;
	num_subset[3] = count_small;
	printf("Big_subset:%d\tSa_subset:%d\tDa_subset:%d\tSmall_subset:%d\n\n", count_big,
			count_sa, count_da, count_small);



/*	 printf("***********************big_ruleset*******************************************\n");
	 if(num_subset[0]!=0)
	 dump_ruleset(subset[0],num_subset[0]);
	 else
	 printf(" big_ruleset is empty!\n");
	 printf("***********************SA_ruleset********************************************\n");
	 dump_ruleset(subset[1],num_subset[1]);
	 printf("***********************DA_ruleset********************************************\n");
	 dump_ruleset(subset[2],num_subset[2]);
	 printf("***********************small_ruleset*******************************************\n");
	 	 if(num_subset[3]!=0)
	 	 dump_ruleset(subset[3],num_subset[3]);
	 	 else
	 	 printf("small_ruleset is empty!\n");*/



}


int Abs_based_Split(trie t, int blocksize) {
	priority_queue<trie::nodeItem> pq;
	queue<trie::nodeItem> q;
	int block_num = 0;
	int total = 0;
	int Cut = 0;
	int empty = 0;
	vector<int> out;
	total = t.nodeSet[t.root].nrules;
	
	q.push(t.nodeSet[t.root]);
	

	while (!q.empty()) {
		trie::nodeItem front = q.front();
		q.pop();
		if (front.abs < blocksize && front.abs >= 0)
			pq.push(front);

		for (unsigned int i = 0; i < front.ncuts; i++) {
			if (front.child[i] != Null)
				q.push(t.nodeSet[front.child[i]]);
		}
	}

	while (t.nodeSet[t.root].nrules > blocksize && !pq.empty()) {
		trie::nodeItem top = pq.top();	
		pq.pop();
		int father = top.father;
		int last = -1;
		while (father != -1) {	
			if (t.nodeSet[father].nrules == -1)
				break;

			t.nodeSet[father].nrules -= top.nrules;
	
			t.nodeSet[father].abs = abs(t.nodeSet[father].nrules - t.nodeSet[father].blocksize);

			if (t.nodeSet[father].abs < blocksize && t.nodeSet[father].nrules > 0)
				last = father;		

			father = t.nodeSet[father].father;
		}
		if (father == -1) {
			if (last != -1)
				pq.push(t.nodeSet[last]);
			out.push_back(top.nrules);
			t.nodeSet[top.id].nrules = -1;
			block_num++;

		}

	}

	if (t.nodeSet[t.root].nrules<=blocksize  && t.nodeSet[t.root].nrules >= 0){
	
		block_num++;
	
		for(int i=0;i<out.size();i++) {

			int temp = 0;
			int temp1 = 0;
			if (out[i] > blocksize)
			{
				temp = out[i] - blocksize;
			}
			Cut = Cut + temp;
			if (out[i] < blocksize)
			{
				temp1 = blocksize - out[i];
			}
			empty += temp1;
		}
		empty = block_num*blocksize - total + Cut;
		printf("general:%d\n",Cut);
		printf("empty: %d\n", empty);
		printf("block_num: %d\n\n",block_num);
		return block_num;

	} else if (t.nodeSet[t.root].nrules < 0) {
		t.nodeSet[t.root].nrules = BLOCKSIZE + t.nodeSet[t.root].nrules;
		for(int i=0;i<out.size();i++) {
					int temp = 0;
					int temp1 = 0;
					if (out[i] > blocksize)
					{	temp = out[i] - blocksize;
					}
					Cut = Cut + temp;
					if (out[i] < blocksize)
					{
						temp1 = blocksize - out[i];
					}
					empty += temp1;
				}
		empty = block_num*blocksize - total + Cut;
		printf("root: %d\n",t.nodeSet[t.root].nrules);
		printf("general:%d\n",Cut);
		printf("empty: %d\n", empty);
		printf("block_num: %d\n\n",block_num);
		return block_num;
	} else {
		block_num ++;
		t.nodeSet[t.root].nrules -= blocksize;
		for(int i=0;i<out.size();i++) {
					int temp = 0;
					int temp1 = 0;
					if (out[i] > blocksize)
					{	temp = out[i] - blocksize;
					}
					Cut = Cut + temp;
					if (out[i] < blocksize)
					{
						temp1 = blocksize - out[i];
					}
					empty += temp1;
				}
		printf("root: %d\n",t.nodeSet[t.root].nrules);
		printf("Cut:%d\n",Cut);
		printf("empty: %d\n", empty);
		printf("block_num: %d\n\n",block_num);
		return block_num;
	}
	return -1;

}

struct cmp {	//升序
    bool operator() (trie::nodeItem a, trie::nodeItem b) {
        if ( a.nrules != b.nrules)
        	return a.nrules < b.nrules;
        return a.layNo > b.layNo;
    }
/*    bool operator() (trie::nodeItem a, trie::nodeItem b) {
        int tmp  = a.nrules - b.nrules;
        if (tmp < 0) return 1;
        else if (tmp == 0) return 0;
        else return -1;
    }*/
};


int level_order_Split (trie t, int blocksize) {
	
	priority_queue<trie::nodeItem, vector<trie::nodeItem>, cmp> pq;
	
	queue<trie::nodeItem> q;
	int total;
	int block_num = 0;
	int empty = 0;
	vector<int> out;
	q.push(t.nodeSet[t.root]);
	total = t.nodeSet[t.root].nrules;
	int j = 0;
	while (!q.empty()) {
		trie::nodeItem front = q.front();
		q.pop();	
		if (front.nrules <= blocksize && front.nrules > 0)
			pq.push(front);
		else if (front.nrules != -1){
			for (unsigned int i = 0; i < front.ncuts; i++) {
				if (front.child[i] != Null && t.nodeSet[front.child[i]].nrules!=-1)
					q.push(t.nodeSet[front.child[i]]);
			}
		}
	}
	
	
	while (t.nodeSet[t.root].nrules > blocksize && !pq.empty()) { 
		trie::nodeItem top = pq.top();
		pq.pop();
		int father = top.father;
		int last = -1;
		int left = -1;
		int last1 = -1;
		left = blocksize - top.nrules;
		int storage = 0;
		while (father != -1) {
			if (t.nodeSet[father].nrules == -1)
				break;
			t.nodeSet[father].nrules -= top.nrules;
			if (t.nodeSet[father].nrules <= blocksize && t.nodeSet[father].nrules > 0)
				last = father;
			father = t.nodeSet[father].father;
		}

		if (father == -1) {
			if (last != -1)
				pq.push(t.nodeSet[last]);
			storage += top.nrules;
			t.nodeSet[top.id].nrules = -1;// delete top
		}

		if (left == 0 || t.nodeSet[t.root].nrules <= blocksize) {
			block_num++;
			out.push_back(storage);
		} else if (t.nodeSet[t.root].nrules > blocksize) {
			priority_queue<trie::nodeItem, vector<trie::nodeItem>, cmp> pq1;
			queue<trie::nodeItem> q1;
			q1.push(t.nodeSet[t.root]);
			int c = 0;
			while (!q1.empty()) {
				trie::nodeItem front = q1.front();
				q1.pop();
				if (front.nrules <= left && front.nrules > 0)
					pq1.push(front);
				else{
					for (unsigned int i = 0; i < front.ncuts; i++) {
						if (front.child[i] != Null && t.nodeSet[front.child[i]].nrules>0){
							q1.push(t.nodeSet[front.child[i]]); 
						}
					}
				}
			}
			
			while(left != 0 && !pq1.empty()) {
				trie::nodeItem top = pq1.top();
				pq1.pop();			
				int father = top.father;
				
				left = left - top.nrules;

				while (father != -1) {
					if (t.nodeSet[father].nrules == -1)
						break;
					if (left < 0)
						break;
					t.nodeSet[father].nrules -= top.nrules;
					if (t.nodeSet[father].nrules <= blocksize && t.nodeSet[father].nrules > 0 && father != last)
						last1 = father;
					father = t.nodeSet[father].father;
				}
				if (father == -1) {
					if (last1 != -1) 
						pq.push(t.nodeSet[last1]);
						
					storage += top.nrules;

					t.nodeSet[top.id].nrules = -1;
				}
			}
			out.push_back(storage);
			block_num++;
		}
	
	}

	block_num++;

	if (t.nodeSet[t.root].nrules > blocksize) {
		printf ("general: %d\n", (t.nodeSet[t.root].nrules -blocksize));
		empty = blocksize*block_num - total + t.nodeSet[t.root].nrules -blocksize;
		printf("root:%d\n",t.nodeSet[t.root].nrules);
		printf("empty:  %d\n",empty);
		printf("block: %d\n\n",block_num);
		return 0;
	}
	printf("root:%d\n",t.nodeSet[t.root].nrules);
	empty = blocksize*block_num - total;
	printf("empty:  %d\n",empty);
	printf("block: %d\n\n",block_num);

	return 0;
}



int main(int argc, char* argv[]) {
	pc_rule *rule;
	int number_rule = 0;
	parseargs(argc, argv);
	char test1;
	while ((test1 = fgetc(fpr)) != EOF)
		if (test1 == '@')
			number_rule++;
	rewind(fpr);
	rule = (pc_rule *) calloc(number_rule, sizeof(pc_rule));
	number_rule = loadrule(fpr, rule);
	printf("the number of rules = %d\n", number_rule);
	fclose(fpr);
	//dump_ruleset(rule,number_rule);

	field_length field_length_ruleset[number_rule];
	count_length(number_rule, rule, field_length_ruleset);


	pc_rule* subset_4[4];
	for (int n = 0; n < 4; n++)
		subset_4[n] = (pc_rule *) malloc(number_rule * sizeof(pc_rule));
	int num_subset_4[4] = { 0, 0, 0, 0};
	int threshold_value_4[2] = { threshold, threshold };
	partition_v3(rule, subset_4,num_subset_4,number_rule,field_length_ruleset,threshold_value_4);

	// tries constructing
	trie T_sa(num_subset_4[1], bucketSize, subset_4[1], 4, 0);	//FitCut的区间选择（小域的区间能否保证规则不出现overlap）
	trie T_da(num_subset_4[2], bucketSize, subset_4[2], 4, 1);
	trie T_small(num_subset_4[3], bucketSize, subset_4[3], 4, 3);
	int a = 0;

	printf("blocksize=%d\n",BLOCKSIZE);	

	printf("\nAbs-base split\n");

	a = Abs_based_Split(T_sa, BLOCKSIZE);
	a = Abs_based_Split(T_da, BLOCKSIZE);
	a = Abs_based_Split(T_small, BLOCKSIZE);

	printf("\nlevel-order split\n");
	a = level_order_Split(T_sa, BLOCKSIZE);
	a = level_order_Split(T_da, BLOCKSIZE);
	a = level_order_Split(T_small, BLOCKSIZE);
	

}
