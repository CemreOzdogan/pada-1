using System.ComponentModel;
using System.Text;
using System.Text.Json;

namespace PadaUI;

internal sealed class MainForm : Form
{
    private enum FieldKind { InputFile, OutputFile, OutputFolder, TextMessage }

    private sealed record FieldSpec(string ArgName, string Label, FieldKind Kind, bool Required);

    private static readonly Dictionary<string, string[]> VariantsByScheme = new()
    {
        ["ML-DSA"] = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"],
        ["ML-KEM"] = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"],
    };

    private static readonly Dictionary<string, string[]> OperationsByScheme = new()
    {
        ["ML-DSA"] = ["Keygen", "Sign", "Verify"],
        ["ML-KEM"] = ["Keygen", "Encapsulate", "Decapsulate"],
    };

    private static readonly Dictionary<(string Scheme, string Op), FieldSpec[]> FieldsByOp = new()
    {
        [("ML-DSA", "Keygen")] =
        [
            new FieldSpec("out-dir", "Output folder (optional — defaults inside pada-1/keys)", FieldKind.OutputFolder, Required: false),
        ],
        [("ML-DSA", "Sign")] =
        [
            new FieldSpec("sk", "Signing key (sk)", FieldKind.InputFile, Required: true),
            new FieldSpec("file", "File to sign (leave blank if typing text below)", FieldKind.InputFile, Required: false),
            new FieldSpec("text", "...or type text to sign", FieldKind.TextMessage, Required: false),
            new FieldSpec("sig-out", "Signature out (blank = default)", FieldKind.OutputFile, Required: false),
        ],
        [("ML-DSA", "Verify")] =
        [
            new FieldSpec("pk", "Public key (pk)", FieldKind.InputFile, Required: true),
            new FieldSpec("file", "Signed file", FieldKind.InputFile, Required: true),
            new FieldSpec("sig", "Signature", FieldKind.InputFile, Required: true),
        ],
        [("ML-KEM", "Keygen")] =
        [
            new FieldSpec("out-dir", "Output folder (optional — defaults inside pada-1/keys)", FieldKind.OutputFolder, Required: false),
        ],
        [("ML-KEM", "Encapsulate")] =
        [
            new FieldSpec("pk", "Public key (pk)", FieldKind.InputFile, Required: true),
            new FieldSpec("ct-out", "Ciphertext out", FieldKind.OutputFile, Required: true),
            new FieldSpec("ss-out", "Shared secret out (optional)", FieldKind.OutputFile, Required: false),
        ],
        [("ML-KEM", "Decapsulate")] =
        [
            new FieldSpec("sk", "Secret key (sk)", FieldKind.InputFile, Required: true),
            new FieldSpec("ct", "Ciphertext", FieldKind.InputFile, Required: true),
            new FieldSpec("ss-out", "Shared secret out (optional)", FieldKind.OutputFile, Required: false),
        ],
    };

    private readonly TextBox _cliPathBox;
    private readonly ComboBox _schemeBox;
    private readonly ComboBox _variantBox;
    private readonly ComboBox _opBox;
    private readonly TableLayoutPanel _fieldsPanel;
    private readonly DataGridView _grid;
    private readonly TextBox _detailBox;

    private readonly List<(TextBox Box, FieldSpec Spec)> _currentFields = [];
    private readonly BindingList<RunRow> _rows = [];

    private sealed record RunRow(string Time, string Scheme, string Op, string Variant, bool Ok, string Duration, string Summary, string RawJson);

    public MainForm()
    {
        Text = "pada-1 — ML-KEM / ML-DSA";
        Width = 900;
        Height = 700;
        StartPosition = FormStartPosition.CenterScreen;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(10),
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 45));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
        Controls.Add(root);

        // --- CLI path row ---
        var cliRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, AutoSize = true };
        cliRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        cliRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        cliRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        cliRow.Controls.Add(new Label { Text = "pqc-cli.exe:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) }, 0, 0);
        _cliPathBox = new TextBox { Dock = DockStyle.Fill, Text = FindDefaultCliPath() ?? string.Empty };
        cliRow.Controls.Add(_cliPathBox, 1, 0);
        var browseCliButton = new Button { Text = "Browse...", AutoSize = true };
        browseCliButton.Click += (_, _) => BrowseForCli();
        cliRow.Controls.Add(browseCliButton, 2, 0);
        root.Controls.Add(cliRow, 0, 0);

        // --- Scheme / variant / op row ---
        var pickerRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 6, AutoSize = true };
        pickerRow.Controls.Add(new Label { Text = "Scheme:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) });
        _schemeBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 100 };
        _schemeBox.Items.AddRange(["ML-DSA", "ML-KEM"]);
        _schemeBox.SelectedIndexChanged += (_, _) => OnSchemeChanged();
        pickerRow.Controls.Add(_schemeBox);

        pickerRow.Controls.Add(new Label { Text = "Variant:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(12, 6, 6, 0) });
        _variantBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
        pickerRow.Controls.Add(_variantBox);

        pickerRow.Controls.Add(new Label { Text = "Operation:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(12, 6, 6, 0) });
        _opBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
        _opBox.SelectedIndexChanged += (_, _) => OnOperationChanged();
        pickerRow.Controls.Add(_opBox);
        root.Controls.Add(pickerRow, 0, 1);

        // --- Dynamic file fields ---
        _fieldsPanel = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 3, AutoSize = true, Padding = new Padding(0, 6, 0, 6) };
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var fieldsHost = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        fieldsHost.Controls.Add(_fieldsPanel);
        var runButton = new Button { Text = "Run", Width = 100, Height = 32, Anchor = AnchorStyles.Right };
        runButton.Click += (_, _) => RunClicked();
        var runRow = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        runRow.Controls.Add(runButton);

        var fieldsGroup = new Panel { Dock = DockStyle.Fill };
        fieldsGroup.Controls.Add(fieldsHost);
        fieldsGroup.Controls.Add(runRow);
        root.Controls.Add(fieldsGroup, 0, 2);

        // --- Results grid ---
        _grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            AutoGenerateColumns = false,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            ReadOnly = true,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
        };
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Time", DataPropertyName = nameof(RunRow.Time), Width = 70 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Scheme", DataPropertyName = nameof(RunRow.Scheme), Width = 70 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Op", DataPropertyName = nameof(RunRow.Op), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Variant", DataPropertyName = nameof(RunRow.Variant), Width = 90 });
        _grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText = "OK", DataPropertyName = nameof(RunRow.Ok), Width = 40 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Duration", DataPropertyName = nameof(RunRow.Duration), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Summary", DataPropertyName = nameof(RunRow.Summary), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _grid.DataSource = _rows;
        _grid.SelectionChanged += (_, _) => OnGridSelectionChanged();
        root.Controls.Add(_grid, 0, 3);

        // --- Detail box ---
        _detailBox = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font(FontFamily.GenericMonospace, 9),
        };
        root.Controls.Add(_detailBox, 0, 4);

        _schemeBox.SelectedIndex = 0;
    }

    private void OnSchemeChanged()
    {
        var scheme = (string)_schemeBox.SelectedItem!;

        _variantBox.Items.Clear();
        _variantBox.Items.AddRange(VariantsByScheme[scheme]);
        _variantBox.SelectedIndex = 0;

        _opBox.Items.Clear();
        _opBox.Items.AddRange(OperationsByScheme[scheme]);
        _opBox.SelectedIndex = 0;
    }

    private void OnOperationChanged()
    {
        _fieldsPanel.Controls.Clear();
        _fieldsPanel.RowStyles.Clear();
        _fieldsPanel.RowCount = 0;
        _currentFields.Clear();

        if (_schemeBox.SelectedItem is not string scheme || _opBox.SelectedItem is not string op)
        {
            return;
        }

        var specs = FieldsByOp[(scheme, op)];
        for (int i = 0; i < specs.Length; i++)
        {
            var spec = specs[i];
            _fieldsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _fieldsPanel.RowCount++;

            _fieldsPanel.Controls.Add(new Label
            {
                Text = spec.Label + (spec.Required ? " *" : ""),
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Padding = new Padding(0, 6, 6, 0),
            }, 0, i);

            TextBox box;
            if (spec.Kind == FieldKind.TextMessage)
            {
                box = new TextBox
                {
                    Multiline = true,
                    Height = 70,
                    ScrollBars = ScrollBars.Vertical,
                    Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                };
            }
            else
            {
                box = new TextBox { Dock = DockStyle.Fill };
            }
            _fieldsPanel.Controls.Add(box, 1, i);

            if (spec.Kind != FieldKind.TextMessage)
            {
                var browse = new Button { Text = "Browse...", AutoSize = true };
                var capturedSpec = spec;
                browse.Click += (_, _) => BrowseForField(box, capturedSpec);
                _fieldsPanel.Controls.Add(browse, 2, i);
            }

            _currentFields.Add((box, spec));
        }
    }

    private static void BrowseForField(TextBox box, FieldSpec spec)
    {
        switch (spec.Kind)
        {
            case FieldKind.OutputFolder:
                using (var dialog = new FolderBrowserDialog())
                {
                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        box.Text = dialog.SelectedPath;
                    }
                }
                break;

            case FieldKind.OutputFile:
                using (var dialog = new SaveFileDialog { OverwritePrompt = false })
                {
                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        box.Text = dialog.FileName;
                    }
                }
                break;

            case FieldKind.InputFile:
            default:
                using (var dialog = new OpenFileDialog())
                {
                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        box.Text = dialog.FileName;
                    }
                }
                break;
        }
    }

    private void BrowseForCli()
    {
        using var dialog = new OpenFileDialog { Filter = "pqc-cli|pqc-cli.exe|All files|*.*" };
        if (dialog.ShowDialog() == DialogResult.OK)
        {
            _cliPathBox.Text = dialog.FileName;
        }
    }

    private void RunClicked()
    {
        if (string.IsNullOrWhiteSpace(_cliPathBox.Text))
        {
            MessageBox.Show(this, "Set the path to pqc-cli.exe first.", "pada-1", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (_schemeBox.SelectedItem is not string scheme || _variantBox.SelectedItem is not string variant || _opBox.SelectedItem is not string op)
        {
            return;
        }

        var schemeArg = scheme == "ML-DSA" ? "ml-dsa" : "ml-kem";
        var opArg = op.ToLowerInvariant();
        var args = new List<string> { schemeArg, opArg, "--variant", variant };

        if (op == "Keygen")
        {
            string? requestedFolder = null;
            foreach (var (box, spec) in _currentFields)
            {
                if (spec.ArgName == "out-dir")
                {
                    requestedFolder = box.Text;
                }
            }

            string folder = ResolveKeygenFolder(requestedFolder, variant);
            try
            {
                Directory.CreateDirectory(folder);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Couldn't create '{folder}':\n{ex.Message}", "pada-1", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            args.Add("--sk-out");
            args.Add(Path.Combine(folder, $"{variant}-sk.bin"));
            args.Add("--pk-out");
            args.Add(Path.Combine(folder, $"{variant}-pk.bin"));
        }
        else if (op == "Sign")
        {
            TextBox? skBox = null, fileBox = null, textBox = null, sigOutBox = null;
            foreach (var (box, spec) in _currentFields)
            {
                switch (spec.ArgName)
                {
                    case "sk": skBox = box; break;
                    case "file": fileBox = box; break;
                    case "text": textBox = box; break;
                    case "sig-out": sigOutBox = box; break;
                }
            }

            if (skBox is null || string.IsNullOrWhiteSpace(skBox.Text))
            {
                MessageBox.Show(this, "'Signing key (sk)' is required.", "pada-1", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            bool hasFile = fileBox is not null && !string.IsNullOrWhiteSpace(fileBox.Text);
            bool hasText = textBox is not null && !string.IsNullOrWhiteSpace(textBox.Text);

            if (hasFile == hasText)
            {
                MessageBox.Show(
                    this,
                    hasFile
                        ? "Provide either a file to sign or typed text — not both."
                        : "Nothing to sign. Pick a file, or type text in the box below.",
                    "pada-1",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            args.Add("--sk");
            args.Add(skBox.Text);

            string fileToSign;
            if (hasFile)
            {
                fileToSign = fileBox!.Text;
            }
            else
            {
                try
                {
                    fileToSign = WriteTypedMessage(textBox!.Text, variant);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, $"Couldn't save typed text:\n{ex.Message}", "pada-1", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            args.Add("--file");
            args.Add(fileToSign);

            if (sigOutBox is not null && !string.IsNullOrWhiteSpace(sigOutBox.Text))
            {
                args.Add("--sig-out");
                args.Add(sigOutBox.Text);
            }
        }
        else
        {
            foreach (var (box, spec) in _currentFields)
            {
                if (spec.Required && string.IsNullOrWhiteSpace(box.Text))
                {
                    MessageBox.Show(this, $"'{spec.Label}' is required.", "pada-1", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }

            foreach (var (box, spec) in _currentFields)
            {
                if (!string.IsNullOrWhiteSpace(box.Text))
                {
                    args.Add("--" + spec.ArgName);
                    args.Add(box.Text);
                }
            }
        }

        CliResult result;
        try
        {
            result = CliRunner.Run(_cliPathBox.Text, args);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Failed to launch pqc-cli:\n{ex.Message}", "pada-1", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        string rawJson = result.StdOut.Length > 0 ? result.StdOut : result.StdErr;
        bool ok = false;
        string summary = rawJson;

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            ok = root.TryGetProperty("ok", out var okProp) && okProp.GetBoolean();
            summary = Summarize(root, ok);
        }
        catch (JsonException)
        {
            summary = string.IsNullOrEmpty(rawJson) ? "(no output)" : rawJson;
        }

        string duration = FormatDuration(result.Elapsed);
        _rows.Insert(0, new RunRow(DateTime.Now.ToString("HH:mm:ss"), scheme, op, variant, ok, duration, summary, rawJson));
        if (_grid.Rows.Count > 0)
        {
            _grid.ClearSelection();
            _grid.Rows[0].Selected = true;
        }
    }

    private static string Summarize(JsonElement root, bool ok)
    {
        if (!ok)
        {
            return root.TryGetProperty("error", out var err) ? err.GetString() ?? "error" : "error";
        }

        if (root.TryGetProperty("valid", out var valid))
        {
            return valid.GetBoolean() ? "signature valid" : "signature INVALID";
        }

        if (root.TryGetProperty("shared_secret_hex", out var ss))
        {
            return "shared secret " + ss.GetString();
        }

        if (root.TryGetProperty("sk_path", out var skPath) && root.TryGetProperty("pk_path", out var pkPath))
        {
            return $"keypair written to {skPath.GetString()} / {pkPath.GetString()}";
        }

        if (root.TryGetProperty("signature_path", out var sigPath))
        {
            string signedFile = root.TryGetProperty("file", out var f) ? f.GetString() ?? "?" : "?";
            return $"signed '{signedFile}', signature at {sigPath.GetString()}";
        }

        return "ok";
    }

    private void OnGridSelectionChanged()
    {
        if (_grid.SelectedRows.Count == 0 || _grid.SelectedRows[0].DataBoundItem is not RunRow row)
        {
            _detailBox.Text = string.Empty;
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(row.RawJson);
            _detailBox.Text = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (JsonException)
        {
            _detailBox.Text = row.RawJson;
        }
    }

    private static string FormatDuration(TimeSpan elapsed) =>
        elapsed.TotalSeconds.ToString("0.000", System.Globalization.CultureInfo.InvariantCulture) + " s";

    private static string ResolveKeygenFolder(string? requestedFolder, string variant)
    {
        if (!string.IsNullOrWhiteSpace(requestedFolder))
        {
            return requestedFolder;
        }

        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        return Path.Combine(FindRepoRoot(), "keys", $"{stamp}_{variant}");
    }

    private static string WriteTypedMessage(string text, string variant)
    {
        var folder = Path.Combine(FindRepoRoot(), "messages");
        Directory.CreateDirectory(folder);

        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var path = Path.Combine(folder, $"{stamp}_{variant}.txt");
        File.WriteAllText(path, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return path;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "engines")) && Directory.Exists(Path.Combine(dir.FullName, "ui")))
            {
                return dir.FullName;
            }
        }

        return AppContext.BaseDirectory;
    }

    private static string? FindDefaultCliPath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            foreach (var config in new[] { "debug", "release" })
            {
                var candidate = Path.Combine(dir.FullName, "engines", "target", config, "pqc-cli.exe");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }
}
