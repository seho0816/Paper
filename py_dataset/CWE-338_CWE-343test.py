# insecure code

import random
import time

class LotteryCard:
    def __init__(self):
        self.winning_number = 0
        self.user_number = 0
        self.prize = 0
    
    def generate(self):
        # Seed with current time - INSECURE!
        random.seed(int(time.time()))
        
        self.winning_number = random.randint(0, 9999)
        self.user_number = random.randint(0, 9999)
        self._calculate_prize()
    
    def _calculate_prize(self):
        difference = abs(self.user_number - self.winning_number)
        
        if self.user_number == self.winning_number:
            self.prize = 1000  # Jackpot
        elif difference < 10:
            self.prize = 100   # Close match
        elif difference < 100:
            self.prize = 10    # Partial match
        else:
            self.prize = 0     # No win
    
    def reveal(self):
        print(f"Your number: {self.user_number:04d}")
        print(f"Winning number: {self.winning_number:04d}")
        
        if self.prize > 0:
            print(f"Congratulations! You won ${self.prize}!")
        else:
            print("Sorry, better luck next time!")

def main():
    print("Welcome to QuickDraw Lucky Lottery!")
    input("Press Enter to scratch your card...")
    
    card = LotteryCard()
    card.generate()
    card.reveal()

if __name__ == "__main__":
    main()