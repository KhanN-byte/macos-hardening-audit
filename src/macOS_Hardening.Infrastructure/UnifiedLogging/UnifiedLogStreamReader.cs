// Frames live JSON array objects incrementally without buffering the entire stream.

using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace macOS_Hardening.Infrastructure.UnifiedLogging;

public sealed class UnifiedLogStreamReader(int maxRecordBytes = 262144, int maxDepth = 32)
{
    public async IAsyncEnumerable<UnifiedLogParseResult> ReadAsync(
        Stream stream, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRecordBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDepth);
        var framer = new Framer(maxRecordBytes, maxDepth);
        var buffer = new byte[8192];
        var index = 0;
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken);
            if (count == 0) break;
            for (var i = 0; i < count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var record = framer.Push(buffer[i]);
                if (record is null) continue;
                using var document = JsonDocument.Parse(record,
                    new JsonDocumentOptions { MaxDepth = maxDepth });
                yield return UnifiedLogParser.ParseRecord(document.RootElement, index);
                // The index describes this connection; it is not a durable record identifier.
                index = index == int.MaxValue ? 0 : index + 1;
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        framer.Complete();
    }

    private sealed class Framer(int limit, int depthLimit)
    {
        private enum State { Start, Banner, FirstObjectOrEnd, NextObject, Object, CommaOrEnd, End }
        private State state;
        private bool bannerSeen;
        private bool inString;
        private bool escaped;
        private int depth;
        private readonly List<byte> pending = new();
        private static bool White(byte value) => value is 9 or 10 or 13 or 32;

        public byte[]? Push(byte value)
        {
            if (state == State.Banner)
            {
                if (pending.Count >= 4096) throw new InvalidDataException("Stream preamble exceeds limit.");
                if (value != 10) { pending.Add(value); return null; }
                var text = Encoding.UTF8.GetString(pending.ToArray()).TrimEnd('\r');
                if (!text.StartsWith("Filtering the log data using \"", StringComparison.Ordinal) ||
                    !text.EndsWith('"'))
                    throw new InvalidDataException("Unsupported stream preamble.");
                pending.Clear();
                bannerSeen = true;
                state = State.Start;
                return null;
            }
            if (state == State.Object)
            {
                if (pending.Count >= limit) throw new InvalidDataException("Stream record exceeds limit.");
                pending.Add(value);
                if (inString)
                {
                    if (escaped) escaped = false;
                    else if (value == (byte)'\\') escaped = true;
                    else if (value == (byte)'"') inString = false;
                }
                else if (value == (byte)'"') inString = true;
                else if (value is (byte)'{' or (byte)'[')
                {
                    if (++depth > depthLimit) throw new InvalidDataException("Stream nesting exceeds limit.");
                }
                else if (value is (byte)'}' or (byte)']')
                {
                    if (--depth == 0)
                    {
                        state = State.CommaOrEnd;
                        var record = pending.ToArray();
                        pending.Clear();
                        return record;
                    }
                }
                return null;
            }
            if (White(value)) return null;
            switch (state)
            {
                case State.Start when value == (byte)'[': state = State.FirstObjectOrEnd; break;
                case State.Start when value == (byte)'F' && !bannerSeen:
                    state = State.Banner; pending.Add(value); break;
                case State.FirstObjectOrEnd when value == (byte)']': state = State.End; break;
                case State.FirstObjectOrEnd or State.NextObject when value == (byte)'{':
                    state = State.Object; depth = 1; pending.Add(value); break;
                case State.CommaOrEnd when value == (byte)',': state = State.NextObject; break;
                case State.CommaOrEnd when value == (byte)']': state = State.End; break;
                default: throw new InvalidDataException("Unexpected stream framing.");
            }
            return null;
        }

        public void Complete()
        {
            if (state != State.End) throw new InvalidDataException("Stream ended before the JSON array was complete.");
        }
    }
}
