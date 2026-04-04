from engine.core import MITMEngine

def main():
    engine = MITMEngine()
    engine.initialize()

    commands = {
        "help" : engine.help,
        "scan": engine.scan,
        "add_target": engine.add_target,
        "targets": engine.show_targets,
        "spoof": engine.start_spoof,
        "stop": engine.stop_spoof,
        "add_module": engine.add_module,
        "dns_add": engine.dns_add
    }

    print("Welcome to MITMSuite")
    print('Enter "help" for available commands.')
    try:
        while True:
            command, *args = input(">> ").split()
            if command in commands:
                commands[command](args)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop_spoof()


if __name__ == "__main__":
    main()