# main.py
from controller import Controller  # assuming your class is in controller.py

if __name__ == "__main__":
    # Initialize controller
    ctrl = Controller()

    # Test URL
    test_url = "https://tg4.tele-gram.shop"

    # Run the main function
    result = ctrl.main(test_url)

    # Print the result
    print(result)
