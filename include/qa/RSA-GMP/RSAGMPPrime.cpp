#include "RSAGMPPrime.h"
#include <iostream>

using namespace RSAGMP;
using namespace RSAGMP::Prime;

//component of Miller-Rabin primality test
inline void MRscomposition(const mpzBigInteger &N, unsigned int &w, mpzBigInteger &z)
{
	 z = N - 1;
	 w = 0;
	 while(mpzBigInteger(z&1) == 0)
	 {
		 w++;
		 z >>= 1;
	 }
}

inline bool MRpredicate1 (const mpzBigInteger &y, const mpzBigInteger &z, const mpzBigInteger &N)
{
 	return (Utils::mod_pow(y,z,N)==1);
}

bool MRpredicate2(const mpzBigInteger &y, const mpzBigInteger &N, const mpzBigInteger &z, const unsigned int &w)
{
	 unsigned int i = 0;
	 mpzBigInteger pow2 = 1;
	 bool cond = mpzBigInteger(Utils::mod_pow(y, z, N)) == mpzBigInteger(N-1);

	 while (!cond && i < w)
	 {
		 i++;
		 pow2 <<= 1;
		 cond = (Utils::mod_pow(y, pow2*z, N) == mpzBigInteger(N-1));
	 }

 	return i != w;
}

//Miller-rabin test for prime number
bool MRtest(const mpzBigInteger &N, unsigned int size, unsigned int precision, TestGenerator *gen)
{
	unsigned int w; mpzBigInteger z;

	MRscomposition(N,w,z);

	bool ris =true;//default result
	unsigned i=0;

	mpzBigInteger y;

	while (ris && i < precision)
	{
	 y = gen->getBig(size) % N;

	 while(y<2)//avoid random number < 2
	 {
		 y = (y + gen->getBig(64)) % N;
	 }
	 ris = (coprime(y,N)) && (MRpredicate1(y, z, N)|| MRpredicate2(y, N, z, w));
	 i++;
	}
	return ris;
}

//extract a random number and search a early prime
mpzBigInteger Prime::NextPrime(mpzBigInteger current, unsigned int size, unsigned int precision)
{
	if(current < 2)
	 return 2;

	auto gen = TestGenerator();
	if (mpzBigInteger(current & 1)==0)
	 current++;

	while (!MRtest(current, size, precision, &gen))
	{
	 current +=2;
	}

	return current;
}

bool Prime::IsPrime(const mpzBigInteger &number, unsigned int size, unsigned int precision)
{
	if(number == 2)
	 return true;
	if(mpzBigInteger(number & 1) == 0 || number < 2)
	 return false;
	auto gen = TestGenerator();
	return MRtest(number, size, precision, &gen);
}

//extract a random number and search a early prime, to use with threads
void Prime::ThreadsNextPrime(mpzBigInteger *current, unsigned int size, unsigned int precision)
{
	if(*current < 2)
	{
	 *current = 2;
	 return;
	}

	auto gen = TestGenerator();
	if (mpzBigInteger(*current & 1)==0)
	 *current += 1;

	while (!MRtest(*current, size, precision, &gen))
	{
	 *current +=2;
	}
}

// Version for worker routine
// Miller-rabin test for prime number
bool WorkersMRtest(const mpzBigInteger &N, unsigned int size, unsigned int precision, std::atomic<bool> *not_found, TestGenerator *gen)
{
 unsigned int w; mpzBigInteger z;

 MRscomposition(N,w,z);

 bool ris =true;//default result
 unsigned i=0;

 mpzBigInteger y;

 while (*not_found && ris && i < precision)
 {
     y = gen->getBig(size) % N;

     while(y<2)//avoid random number < 2
     {
         y = (y + gen->getBig(64)) % N;
     }
     ris = coprime(y,N) && (MRpredicate1(y, z, N)|| (MRpredicate2(y, N, z, w)));
     i++;
 }
 return ris;
}

void WorkerRoutine(mpzBigInteger *current, int size, unsigned int precision, int id, int increment, std::atomic<bool> *not_found)
{
    mpzBigInteger number = *current + 2*id;
    auto gen = TestGenerator();

    while (*not_found && !WorkersMRtest(number, size, precision, not_found, &gen))
    {
        number += increment;
    }

    bool expected = true;
    if(not_found->compare_exchange_strong(expected, false))
    {
        *current = number;
    }
}

//extract a random number and search a early prime using more threads
void Prime::ParallelNextPrime(mpzBigInteger *current, unsigned int size, unsigned int precision, int threads)
{
    if(*current < 2)
    {
        *current = 2;
        return;
    }
    if(mpzBigInteger(*current & 1) == 0)
        (*current)++;

    std::atomic<bool> not_found;
    not_found = true;
    std::thread *workers = new std::thread[threads];

    for(int i = 0; i<threads; i++)
    {
        workers[i] = std::thread(WorkerRoutine, current, size, precision, i, 2*threads, &not_found);
    }

    for(int i = 0; i<threads; i++)
    {
        workers[i].join();
    }

    delete[] workers;
}
