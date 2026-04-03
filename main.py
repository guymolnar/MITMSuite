from engine import MITMEngine

def main():
    engine = MITMEngine()
    engine.initialize()

    commands = {
        "scan": engine.scan,
        "set_target": engine.set_target,
        "targets": engine.show_targets,
        "spoof": engine.start_spoof,
        "stop": engine.stop_spoof,
    }

    print("Welcome to MITMSuite")
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