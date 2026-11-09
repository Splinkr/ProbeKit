"""Worker privado: entrada/saída JSON limitada, sem pickle ou comandos de shell."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scanner.transport import FRAME_LIMIT, TransportError, collect, session


def main():
    def emit(frame):
        content = (json.dumps(frame) + '\n').encode('utf-8')
        if len(content) > FRAME_LIMIT:
            raise TransportError('metadata_limit')
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.flush()

    with session() as connection:
        emit({'ready': True})
        while True:
            line = sys.stdin.buffer.readline(FRAME_LIMIT + 1)
            if not line:
                break
            if len(line) > FRAME_LIMIT or not line.endswith(b'\n'):
                break
            try:
                command = json.loads(line)
                collect(connection, **command, emit=emit)
            except TransportError as error:
                emit({'error': error.kind})
            except Exception:
                emit({'error': 'execution_error'})


if __name__ == '__main__':
    main()
