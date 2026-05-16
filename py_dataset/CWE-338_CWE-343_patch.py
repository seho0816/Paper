import secrets

class LotteryCard:
    def __init__(self):
        self.winning_number = 0
        self.user_number = 0
        self.prize = 0

    def generate(self):
        # [PATCH CWE-338 / CWE-343]
        # 취약점: random.seed(int(time.time())) 은 현재 시각으로 시드를 설정하므로
        # 공격자가 요청 시각을 알면 당첨 번호를 예측할 수 있음.
        #
        # 수정: secrets.randbelow()는 운영체제가 제공하는 암호학적으로 안전한
        # 난수 소스(CSPRNG, /dev/urandom 등)를 사용하므로 예측 불가능.
        self.winning_number = secrets.randbelow(10000)
        self.user_number = secrets.randbelow(10000)
        self._calculate_prize()

    def _calculate_prize(self):
        difference = abs(self.user_number - self.winning_number)

        if self.user_number == self.winning_number:
            self.prize = 1000
        elif difference < 10:
            self.prize = 100
        elif difference < 100:
            self.prize = 10
        else:
            self.prize = 0

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