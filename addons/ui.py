

class Ui:

  def load():
    try:
      import sys
      import time 
      while True:
        sys.stdout.write('\r[|]')
        time.sleep(0.1)
        sys.stdout.write('\r[/]')
        time.sleep(0.1)
        sys.stdout.write('\r[-]')
        time.sleep(0.1)
        sys.stdout.write('\r[\\]')
        time.sleep(0.1)
    except Exception as e:
        print(e)