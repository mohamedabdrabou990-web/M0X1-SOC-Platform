from banner import show_banner, loading
from menu import show_menu
from modules import network_scanner
from modules import process_monitor
from modules import log_analyzer
from modules import ioc_scanner
from modules import alert_manager
from modules import threat_intelligence
from modules import live_monitor
from modules import dashboard
from modules import reports
from modules import incident_response

show_banner()
loading()

while True:
    show_banner()

    choice = show_menu()

    if choice == "1":
        network_scanner.run()

    elif choice == "2":
        process_monitor.run()

    elif choice == "3":
        log_analyzer.run()

    elif choice == "4":
        ioc_scanner.run()

    elif choice == "5":
        alert_manager.run()

    elif choice == "6":
        threat_intelligence.run()

    elif choice == "7":
        live_monitor.run()

    elif choice == "8":
        dashboard.run()

    elif choice == "9":
        reports.run()

    elif choice == "10":
        incident_response.run()


    elif choice == "0":
        print("\nGood Bye 👋")
        break

    else:
        print(f"\nModule ({choice}) is under development...")
        input("\nPress Enter to continue...")