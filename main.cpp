#include <iostream>
#include "md5.h"
#include <fstream>
using namespace std;

//     void printAllKLengthRec(char set[], string prefix,
//                                     int n, int k)
// {
     
//     // Base case: k is 0,
//     // print prefix
//     if (k == 0)
//     {
//         cout << (prefix) << endl;
//         return;
//     }
 
//     // One by one add all characters
//     // from set and recursively
//     // call for k equals to k-1
//     for (int i = 0; i < n; i++)
//     {
//         string newPrefix;
         
//         // Next character of input added
//         newPrefix = prefix + set[i];
         
//         // k is decreased, because
//         // we have added a new character
//         printAllKLengthRec(set, newPrefix, n, k - 1);
//     }
 
// }
 
// void printAllKLength(char set[], int k,int n)
// {
//     printAllKLengthRec(set, "", n, k);
// }         

int main(int argc, char** argv){
    unsigned int state[4] = {0x67452301, 0xefcdab89, 0x98fadcfe, 0x10325476};
    unsigned int precomputed[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                                    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                                    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                                    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                                    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                                    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                                    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                                    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                                    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                                    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                                    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                                    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                                    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                                    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                                    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                                    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
    /*const std::string result = "4f8595ed656b1233f1fdd91fbd692bb7";  
    std::string hash;
    unsigned int tmp;
    for(int i=0;i<4;i++){
        tmp = 0x00000001;
        for (int j=0; j<32; j++){
            state[i]^=tmp;
            //std::cout<<"state " << std::hex <<  state[i] << "\n";
            if ((hash = md5(argv[1], precomputed, state))==result) {
                std::cout<<"i "<< i << "\n";
                std::cout<<"j "<< j << "\n";
                std::cout<<"tmp " << std::hex << tmp << "\n";
                std::cout << "zmieniony state z "<< std::hex << (state[i]^tmp) << " na " << state[i] << std::endl;
                break;
            }
            else {
                state[i]^=tmp;
                tmp = tmp << 1;
            }
        }
    }       


    unsigned int tmp2;
    for(int i=0;i<64;i++){
        tmp2 = 0x00000001;
        for (int j=0; j<32; j++){
            precomputed[i]^=tmp2;
            if ((hash = md5(argv[1], precomputed, state))==result) {
                std::cout<<"i "<< i << "\n";
                std::cout<<"j "<< j << "\n";
                std::cout<<"tmp2 " << tmp2 << "\n";
                std::cout << "zmieniony precomputed z "<< std::hex << (precomputed[i]^tmp) << " na " << precomputed[i] << std::endl;
                break;
            }
            else {
                precomputed[i]^=tmp2;
                tmp2 = tmp2 << 1;
            }
        }
    }  */
    
   

    // cout << "First Test" << endl;
    // char set1[] = {'R', 'r', 'i', 'I', 's', 'S', 'c', 'C', '-', '5', 'V', 'z', 'Z', '3'};
    // int k = 6;

    // for(int i=0; i<10 ;i++){
    //     printAllKLength(set1, i, 14);
    // }
    ifstream file;
    file.open("Polish.dic", ios::in);
    //const std::string result = "4f8595ed656b1233f1fdd91fbd692bb7"; 
    const std::string result = "d941946038347b75014587883f41a0ac";
    std::string line ="";
    while (!file.eof()){
        getline(file, line);
        if(md5(line,precomputed,state)==result){
            std::cout<<line;
            break;
        }
    }
    file.close();
    //std::cout << "md5 of "<< argv[1] << " "<< md5(argv[1], precomputed, state) << std::endl;
    //std::cout << "md5 of "<< "RISC-5 " << " "<< md5("RISC-5", precomputed, state) << std::endl;
    return 0;
}