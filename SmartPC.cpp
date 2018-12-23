//============================================================================
// Name        : SmartPC.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
// Important tips: If you want to run SmartPC, please modify the Makefile.
//============================================================================

#include <iostream>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<math.h>
#include<list>
#include"SmartPC.h"
#include "common.h"
#include "stdinc.h"
#include <sys/time.h>
#include"trie.h"
#include "string.h"

using namespace std;

struct timeval	gStartTime,gEndTime;

FILE *fpr = fopen("./MyFilters100kipc2", "r");           // ruleset file
int bucketSize = 2;   // leaf threashold
int threshold = 16;   // Assume T_SA=T_DA=threshold

pc_entry *P;
int num_entry = 0;
pc_rule *rule;
int number_rule = 0;
int num_general = 0;

int ExpandPreEntry(pc_rule* i, pc_entry* j, int index, pc_entry* expandEntry);

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
      //if(fscanf(fp,"@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\n", &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &rule[number_rule].field[2].low, &rule[number_rule].field[2].high, &rule[number_rule].field[3].low, &rule[number_rule].field[3].high,&protocal, &protocol_mask)!= 16) break;
	
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

	   rule[number_rule].isDone = 0;
	   rule[number_rule].isGeneral = 0;
       rule[number_rule].isCovered = 0;
	   rule[number_rule].id = number_rule;
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
    fprintf (stderr, "Type \"EcoCAM -h\" for help\n");
    exit(1);
     }

   //printf("Bucket Size =  %d\n", bucketSize);
   //printf("Threshold = %d,%d\n", threshold,threshold);
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


void smartPC (pc_rule *rule, int number_rule, int blocksize) {

	int rule_num = 0;
	rule_num = number_rule;

	for (int i = 0; i < number_rule; i++) {
		rule[i].isDone = 0;
		rule[i].isGeneral = 0;
	}

	int d = 0;
	unsigned threshold = (unsigned) pow(2, 16);

	unsigned int lo;
	unsigned int hi;
	int general = 0;
	int mask;

	while (rule_num > blocksize) {


		int sm = 0;
		int flag = 1;
		for (int i = 0; i < number_rule; i++) {
			int done = 0;
			if (!rule[i].isDone && !rule[i].isGeneral) {	//choose pre-entries
//
				if (rule[i].field[0].high - rule[i].field[0].low > rule[i].field[1].high - rule[i].field[1].low)
					d = 1;
				if (rule[i].field[d].high - rule[i].field[d].low > threshold)
					break;


				lo = rule[i].field[d].low;
				hi = rule[i].field[d].high; //printf("i: %d... lo: %u... hi: %u  aaaaa \n", i, lo , hi);

				unsigned int r = hi -lo +1;
				int i = 0;
				while (r >0) {
					r = r>>1;
					i++;
				}

				hi = lo + (1<<i) - 1;
				lo = lo - (1<<i);//printf("i:%d,   hin: %u    lon: %u \n",i,hi ,lo);
				while (!done){
					flag = 1;
					sm = 0;
					for (int j = 0; j < number_rule; j++) {		//the number of rules
						if (!rule[i].isDone && !rule[i].isGeneral) {
			                if(rule[j].field[d].low >=lo && rule[j].field[d].high <=hi)
			                   sm++;
						}
					}

					if (sm < blocksize){ 						//expanding range
/*						if ((lo >> (i-1))&1) {
							lo = lo - (1<<i);
						} else {
							hi = lo + (1<<i) - 1;
						}
						i++;*/
						lo = lo/2;
						hi = hi*2;
						printf("sm :%d\n",sm);
					} else {
						printf("sm1 :%d\n",sm);
						done = 1;
					}
				}
				printf("lo: %u.. hi: %u\n",lo, hi);
			}
			if (done == 1)
				break;

		}
		printf("lo: %u.. hi: %u\n",lo, hi);
		for (int i = 0; i < number_rule; i++) {				//move rules
			if (!rule[i].isDone && !rule[i].isGeneral) {
				if (rule[i].field[d].low >=lo && rule[i].field[d].high <=hi){
					//printf("%d  ", i);
					rule[i].isDone = 1;

				}
			}
		}

		rule_num -= sm; //printf("%d\n", rule_num);

	}

}




int isCovered(pc_rule* rule,pc_entry* entry){
	int isCovered = 0;
	if((rule->field[0].low >= entry->field[0].low) && (rule->field[0].high <= entry->field[0].high) &&
	   (rule->field[1].low >= entry->field[1].low) && (rule->field[1].high <= entry->field[1].high)){
		isCovered = 1;
	}
	return isCovered;
}
int intercept(pc_rule* i, pc_entry* j)
{
	if((i->field[0].low <= j->field[0].high)&&(i->field[0].high >= j->field[0].low))
	{
		if(j->field[1].high < i->field[1].low)
			return 0;
		else if(j->field[1].low > i->field[1].high)
			return 0;
		else
			return 1;
	}
	/*if((i->field[0].low <= j->field[0].high)&&(i->field[0].high >= j->field[0].high))
	{
		if(j->field[1].high < i->field[1].low)
			return 0;
		else if(j->field[1].low > i->field[1].high)
			return 0;
		else
			return 1;
	}*/
	return 0;
	/*if((i->field[0].high < j->field[0].low) || (i->field[0].low > j->field[0].high) ||
			(i->field[1].high < j->field[1].low) || (i->field[1].low > i->field[1].high)){
		return 0;
	} else return 1;*/
}

int Is_entryoverlap(pc_entry * j, int index)
{
	int i;
	for(i = 0; i< num_entry; i++)
	{
		if(i==index) continue;
		if((P[i].field[0].low <= j->field[0].high)&&(P[i].field[0].high >= j->field[0].low))
		{
			if(j->field[1].high < P[i].field[1].low)
				continue;
			else if(j->field[1].low > P[i].field[1].high)
				continue;
			else
				return 1;
		}
		/*if((P[i].field[0].low <= j->field[0].high)&&(P[i].field[0].high >= j->field[0].high))
		{
			if(j->field[1].high < P[i].field[1].low)
				continue;
			else if(j->field[1].low > P[i].field[1].high)
				continue;
			else
				return 1;
		}*/
		/*if((P[i].field[0].low <= j->field[0].high)&&(P[i].field[0].low >= j->field[0].low))
		{
			if(j->field[1].high < P[i].field[1].low)
				continue;
			else if(j->field[1].low > P[i].field[1].high)
				continue;
			else
				return 1;
		}
		if((P[i].field[0].high <= j->field[0].high)&&(P[i].field[0].high >= j->field[0].low))
		{
			if(j->field[1].high < P[i].field[1].low)
				continue;
			else if(j->field[1].low > P[i].field[1].high)
				continue;
			else
				return 1;
		}*/

	}
	return 0;
}

int RuleConflict(int index, int rid, pc_entry* expandEntry){
	pc_entry tmp;
	for(int k = 0; k < number_rule; k++){
		if(rule[k].isGeneral || rule[k].isDone || rule[k].isCovered || (!isCovered(&rule[k],expandEntry)&&(!intercept(&rule[k],expandEntry)))){
			continue;
		}
		if(isCovered(&rule[k],expandEntry)){
			expandEntry->size++;
            rule[k].isCovered = rid;
			if(expandEntry->size > BLOCKSIZE)
            {
                for(int t = 0; t < number_rule; t++) if(rule[t].isCovered == rid) rule[t].isCovered = 0;
                return 1;
            }
            continue;
		} else if(intercept(&rule[k],expandEntry)){
			//tmp = expandEntry;
			memcpy(&tmp,expandEntry, sizeof(pc_entry));
			if(ExpandPreEntry(&rule[k],&tmp,index,expandEntry)) break;
			else
				//expandEntry = tmp;
			    memcpy(expandEntry,&tmp, sizeof(pc_entry));

		}
        //for(int t = 0; t < number_rule; t++) if(rule[t].isCovered != rid) rule[t].isCovered = 0;
	}
	return 0;
}


int ExpandPreEntry(pc_rule* i, pc_entry* j, int  index, pc_entry* expandEntry)
{
	pc_entry temp;
	memcpy(&temp,expandEntry,sizeof(pc_entry));
	//temp = expandEntry;

	expandEntry->field[0].low = i->field[0].low > j->field[0].low ? j->field[0].low:i->field[0].low;
	expandEntry->field[0].high = i->field[0].high < j->field[0].high ? j->field[0].high:i->field[0].high;
	expandEntry->field[1].low = i->field[1].low > j->field[1].low ? j->field[1].low:i->field[1].low;
	expandEntry->field[1].high = i->field[1].high < j->field[1].high ? j->field[1].high:i->field[1].high;

	expandEntry->size += 1;
	i->isDone = 1;
	if(expandEntry->size > BLOCKSIZE)
	{
		i->isGeneral = 1;
		num_general++;
		//printf("general-- rule id = %d\n",i->id);
		memcpy(expandEntry,&temp,sizeof(pc_entry));
		//expandEntry = temp;
		return 0;
	}
	if(Is_entryoverlap(expandEntry,index) || RuleConflict(index, i->id, expandEntry))
	{
		if(intercept(i,j)){
			i->isGeneral = 1;
			num_general++;
			//printf("general-- rule id = %d\n",i->id);
		}
		memcpy(expandEntry,&temp,sizeof(pc_entry));
		i->isDone = 0;
		//expandEntry = temp;
		return 0;
	}

    //printf("rule id = %d   entry_id = %d\n",i->id,index);
	return 1;
}

int BuildPreClassifier(pc_rule *rule, int number_rule, pc_entry *P){
	int i,j;
	int success;

	pc_entry expandedEntry;


	for(i = 0; i < number_rule; i++){
		//printf("584 rule:%d ne:%d\n",i,num_entry);
		success = 0;
		if(rule[i].isDone || rule[i].isGeneral){
			//printf("587 done:%d general:%d\n",rule[i].isDone,rule[i].isGeneral);
			continue;
		}

		for(j = 0; j < num_entry; j++){
			//printf("590 rule:%d,entry:%d\n",i,j);
			if(P[j].size == BLOCKSIZE){
				continue;
			}
			//expandedEntry = P[j];
			memcpy(&expandedEntry,&P[j], sizeof(pc_entry));
			if(ExpandPreEntry(&rule[i],&P[j],j, &expandedEntry)){

				//printf("597 rule:%d,entry:%d\n",i,j);
				success = 1;
				//P[j] = expandedEntry;
				memcpy(&P[j],&expandedEntry, sizeof(pc_entry));
				for(int k = 0; k < number_rule; k++){
					if(isCovered(&rule[k],&P[j])){
						rule[k].isDone = 1;
						//printf("612 rule:%d,entry:%d\n",k,j);
					}
				}
				if(success) break;
			}
			if(rule[i].isGeneral) break;
            for(int t = 0; t < number_rule; t++) rule[t].isCovered = 0;
		}
        for(int t = 0; t < number_rule; t++) rule[t].isCovered = 0;
		if(!success && !rule[i].isGeneral){ //new entry
			rule[i].isDone = 1;
			P[num_entry].size = 1;
			//P[num_entry].ruleid[P[num_entry].size-1] = i;
			P[num_entry].field[0].low = rule[i].field[0].low;
			P[num_entry].field[0].high = rule[i].field[0].high;
			P[num_entry].field[1].low = rule[i].field[1].low;
			P[num_entry].field[1].high = rule[i].field[1].high;

			num_entry++;
			//printf("\nline 622 ----- num_entry = %d\n",num_entry);

		}

	}


	return  num_entry; //the number of TCAM entrise

}






int main(int argc, char* argv[]) {
	parseargs(argc, argv);
	char test1;
	while ((test1 = fgetc(fpr)) != EOF)
		if (test1 == '@')
			number_rule++;
	rewind(fpr);
	rule = (pc_rule *) calloc(number_rule, sizeof(pc_rule));
	number_rule = loadrule(fpr, rule);

	fclose(fpr);


	field_length field_length_ruleset[number_rule];
	count_length(number_rule, rule, field_length_ruleset); //ͳ��ÿ����򳤶�

	printf("the number of rules = %d\n\n", number_rule);

	printf("blocksize=%d\n\n",BLOCKSIZE);

	P = (pc_entry *) malloc(20000 * sizeof(pc_entry));
	BuildPreClassifier(rule,number_rule,P);

	printf("\nline 632 ----- num_entry = %d\n",num_entry);
	//printf("\nline 633 ----- P[0].size = %d\n",P[0].size);
	int count=0;
	for(int i=0;i<num_entry;i++){
		count+=P[i].size;
		//printf("size of entry %d = %d\n",i,P[i].size);
	}


	int empty = BLOCKSIZE * num_entry - count;
    double per = num_general*1.0/number_rule*100;
	printf("\nline 674 ----- count = %d  general = %d  general_percentage = %lf %% empty = %d\n",count,num_general,per,empty);

}
