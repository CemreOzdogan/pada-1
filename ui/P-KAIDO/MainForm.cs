using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace PKaido;

internal sealed class MainForm : Form
{
    // Kaido-inspired palette: near-black indigo, azure dragon-scale blue, gold horns/eyes as the warm accent.
    private static readonly Color BgColor = ColorTranslator.FromHtml("#14141C");
    private static readonly Color PanelColor = ColorTranslator.FromHtml("#1F2233");
    private static readonly Color InputBgColor = ColorTranslator.FromHtml("#161A24");
    private static readonly Color BorderColor = ColorTranslator.FromHtml("#3A4160");
    private static readonly Color TextColor = ColorTranslator.FromHtml("#E8E6DE");
    private static readonly Color SecondaryTextColor = ColorTranslator.FromHtml("#8891A8");
    private static readonly Color AccentColor = ColorTranslator.FromHtml("#2E7FD9");
    private static readonly Color AccentHoverColor = ColorTranslator.FromHtml("#4FA3F5");
    private static readonly Color GoldColor = ColorTranslator.FromHtml("#D4A94E");
    private static readonly Color ErrorColor = ColorTranslator.FromHtml("#C23B3B");

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
            new FieldSpec("out-dir", "Output folder (optional — defaults inside P-KAIDO/keys)", FieldKind.OutputFolder, Required: false),
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
            new FieldSpec("out-dir", "Output folder (optional — defaults inside P-KAIDO/keys)", FieldKind.OutputFolder, Required: false),
        ],
        [("ML-KEM", "Encapsulate")] =
        [
            new FieldSpec("pk", "Public key (pk)", FieldKind.InputFile, Required: true),
            new FieldSpec("ct-out", "Ciphertext out (optional — defaults inside P-KAIDO/keys)", FieldKind.OutputFile, Required: false),
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
    private readonly FlowLayoutPanel _enginePanel;
    private readonly FlowLayoutPanel _variantPanel;
    private readonly FlowLayoutPanel _operationPanel;
    private readonly TableLayoutPanel _fieldsPanel;
    private readonly DataGridView _grid;
    private readonly TextBox _detailBox;

    private readonly List<(TextBox Box, FieldSpec Spec)> _currentFields = [];
    private readonly BindingList<RunRow> _rows = [];

    private sealed record RunRow(string Time, string Scheme, string Op, string Variant, string Engine, bool Ok, string Duration, string Summary, string RawJson);

    public MainForm()
    {
        Text = "P-KAIDO";
        Width = 1180;
        Height = 700;
        StartPosition = FormStartPosition.CenterScreen;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 9,
            Padding = new Padding(10),
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // cli path
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // scheme
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // engine
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // variant
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // operation
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // dynamic fields + run button
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // drop-a-file-to-inspect zone
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // results grid + JSON detail, side by side — takes all remaining space
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // footer
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

        // --- Scheme row ---
        var schemeRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true };
        schemeRow.Controls.Add(new Label { Text = "Scheme:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) });
        _schemeBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 100 };
        _schemeBox.Items.AddRange(["ML-DSA", "ML-KEM"]);
        _schemeBox.SelectedIndexChanged += (_, _) => OnSchemeChanged();
        schemeRow.Controls.Add(_schemeBox);
        root.Controls.Add(schemeRow, 0, 1);

        // --- Engine row: which crypto backend to use (RustCrypto or libcrux) ---
        var engineRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true };
        engineRow.Controls.Add(new Label { Text = "Engine:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) });
        _enginePanel = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
        };
        string[] engines = ["rustcrypto", "libcrux"];
        for (int i = 0; i < engines.Length; i++)
        {
            _enginePanel.Controls.Add(new RadioButton
            {
                Text = engines[i],
                AutoSize = true,
                Checked = i == 0,
                Margin = new Padding(0, 4, 16, 4),
            });
        }
        engineRow.Controls.Add(_enginePanel);
        root.Controls.Add(engineRow, 0, 2);

        // --- Variant row: all options shown at once, no dropdown/scrolling ---
        var variantRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true };
        variantRow.Controls.Add(new Label { Text = "Variant:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) });
        _variantPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
        };
        variantRow.Controls.Add(_variantPanel);
        root.Controls.Add(variantRow, 0, 3);

        // --- Operation row: all options shown at once, no dropdown/scrolling ---
        var operationRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true };
        operationRow.Controls.Add(new Label { Text = "Operation:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) });
        _operationPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
        };
        operationRow.Controls.Add(_operationPanel);
        root.Controls.Add(operationRow, 0, 4);

        // --- Dynamic file fields ---
        // Every field must always be fully visible — no internal scrollbar. Plain Panels with
        // Dock=Fill children don't report their content size upward for AutoSize rows to use,
        // so this whole area is built from AutoSize-aware TableLayoutPanels/FlowLayoutPanels.
        _fieldsPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(0, 6, 0, 6),
        };
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var runButton = new Button { Text = "Run", Width = 100, Height = 32, Anchor = AnchorStyles.Right };
        runButton.FlatStyle = FlatStyle.Flat;
        runButton.BackColor = AccentColor;
        runButton.ForeColor = TextColor;
        runButton.FlatAppearance.BorderColor = AccentHoverColor;
        runButton.FlatAppearance.MouseOverBackColor = AccentHoverColor;
        runButton.Click += (_, _) => RunClicked();
        var runRow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        runRow.Controls.Add(runButton);

        var fieldsGroup = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
        };
        fieldsGroup.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        fieldsGroup.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        fieldsGroup.Controls.Add(_fieldsPanel, 0, 0);
        fieldsGroup.Controls.Add(runRow, 0, 1);
        root.Controls.Add(fieldsGroup, 0, 5);

        // --- Drop a file here to view its hex, no need to run it through an operation ---
        var inspectZone = new Label
        {
            Text = "Drop a file here to view its hex (or click to browse)",
            Dock = DockStyle.Fill,
            Height = 32,
            TextAlign = ContentAlignment.MiddleCenter,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = PanelColor,
            ForeColor = SecondaryTextColor,
            Cursor = Cursors.Hand,
            AllowDrop = true,
            Margin = new Padding(0, 4, 0, 4),
        };
        inspectZone.DragEnter += (_, e) =>
        {
            e.Effect = e.Data is not null && e.Data.GetDataPresent(DataFormats.FileDrop)
                ? DragDropEffects.Copy
                : DragDropEffects.None;
        };
        inspectZone.DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] paths)
            {
                foreach (var path in paths)
                {
                    InspectFile(path);
                }
            }
        };
        inspectZone.Click += (_, _) => BrowseAndInspectFile();
        root.Controls.Add(inspectZone, 0, 6);

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
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Engine", DataPropertyName = nameof(RunRow.Engine), Width = 80 });
        _grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText = "OK", DataPropertyName = nameof(RunRow.Ok), Width = 40 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Duration", DataPropertyName = nameof(RunRow.Duration), Width = 80 });
        var summaryColumn = new DataGridViewTextBoxColumn { HeaderText = "Summary", DataPropertyName = nameof(RunRow.Summary), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill };
        _grid.Columns.Add(summaryColumn);

        _grid.BackgroundColor = PanelColor;
        _grid.GridColor = BorderColor;
        _grid.BorderStyle = BorderStyle.FixedSingle;
        _grid.EnableHeadersVisualStyles = false;
        _grid.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = BgColor,
            ForeColor = TextColor,
            SelectionBackColor = BgColor,
            SelectionForeColor = TextColor,
        };
        _grid.DefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = PanelColor,
            ForeColor = TextColor,
            SelectionBackColor = AccentColor,
            SelectionForeColor = TextColor,
        };
        _grid.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle { BackColor = InputBgColor };
        _grid.RowHeadersDefaultCellStyle.SelectionBackColor = BgColor;

        _grid.CellFormatting += (_, e) =>
        {
            if (e.ColumnIndex != summaryColumn.Index || _grid.Rows[e.RowIndex].DataBoundItem is not RunRow row)
            {
                return;
            }

            e.CellStyle!.ForeColor = row.Ok ? GoldColor : ErrorColor;
        };

        _grid.DataSource = _rows;
        _grid.SelectionChanged += (_, _) => OnGridSelectionChanged();

        // --- Detail box ---
        _detailBox = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font(FontFamily.GenericMonospace, 9),
        };

        // --- Results row: grid on the left, JSON detail on the right, draggable splitter between them ---
        var resultsSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterWidth = 6,
        };
        resultsSplit.Panel1.Controls.Add(_grid);
        resultsSplit.Panel2.Controls.Add(_detailBox);
        root.Controls.Add(resultsSplit, 0, 7);
        // Panel min sizes and SplitterDistance can't be set reliably until the control has its
        // real, laid-out width (it's still the default 150x150 stub during construction).
        Load += (_, _) =>
        {
            resultsSplit.Panel1MinSize = 300;
            resultsSplit.Panel2MinSize = 200;
            resultsSplit.FixedPanel = FixedPanel.Panel2;
            resultsSplit.SplitterDistance = Math.Max(resultsSplit.Panel1MinSize, resultsSplit.Width - 320 - resultsSplit.SplitterWidth);
        };

        // --- Footer ---
        var footerLabel = new Label
        {
            Text = "post kuantum algoritma işlem deney ortamı",
            Dock = DockStyle.Fill,
            AutoSize = true,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = SecondaryTextColor,
            Padding = new Padding(0, 6, 0, 0),
        };
        root.Controls.Add(footerLabel, 0, 8);

        BackColor = BgColor;
        ForeColor = TextColor;
        ThemeTree(this);

        _schemeBox.SelectedIndex = 0;
    }

    private void OnSchemeChanged()
    {
        var scheme = (string)_schemeBox.SelectedItem!;

        _variantPanel.Controls.Clear();
        var variants = VariantsByScheme[scheme];
        for (int i = 0; i < variants.Length; i++)
        {
            var radio = new RadioButton
            {
                Text = variants[i],
                AutoSize = true,
                Checked = i == 0,
                Margin = new Padding(0, 4, 16, 4),
            };
            ThemeControl(radio);
            _variantPanel.Controls.Add(radio);
        }

        _operationPanel.Controls.Clear();
        var operations = OperationsByScheme[scheme];
        for (int i = 0; i < operations.Length; i++)
        {
            var radio = new RadioButton
            {
                Text = operations[i],
                AutoSize = true,
                Checked = i == 0,
                Margin = new Padding(0, 4, 16, 4),
            };
            radio.CheckedChanged += (sender, _) =>
            {
                if (((RadioButton)sender!).Checked)
                {
                    OnOperationChanged();
                }
            };
            ThemeControl(radio);
            _operationPanel.Controls.Add(radio);
        }

        OnOperationChanged();
    }

    private string? GetSelectedVariant() =>
        _variantPanel.Controls
            .OfType<RadioButton>()
            .FirstOrDefault(r => r.Checked)?.Text;

    private string? GetSelectedOperation() =>
        _operationPanel.Controls
            .OfType<RadioButton>()
            .FirstOrDefault(r => r.Checked)?.Text;

    private string? GetSelectedEngine() =>
        _enginePanel.Controls
            .OfType<RadioButton>()
            .FirstOrDefault(r => r.Checked)?.Text;

    private void OnOperationChanged()
    {
        _fieldsPanel.Controls.Clear();
        _fieldsPanel.RowStyles.Clear();
        _fieldsPanel.RowCount = 0;
        _currentFields.Clear();

        if (_schemeBox.SelectedItem is not string scheme || GetSelectedOperation() is not string op)
        {
            return;
        }

        var specs = FieldsByOp[(scheme, op)];
        for (int i = 0; i < specs.Length; i++)
        {
            var spec = specs[i];
            _fieldsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _fieldsPanel.RowCount++;

            var label = new Label
            {
                Text = spec.Label + (spec.Required ? " *" : ""),
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Padding = new Padding(0, 6, 6, 0),
            };
            ThemeControl(label);
            _fieldsPanel.Controls.Add(label, 0, i);

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
            ThemeControl(box);
            _fieldsPanel.Controls.Add(box, 1, i);

            if (spec.Kind != FieldKind.TextMessage)
            {
                var browse = new Button { Text = "Browse...", AutoSize = true };
                var capturedSpec = spec;
                browse.Click += (_, _) => BrowseForField(box, capturedSpec);
                ThemeControl(browse);
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
            MessageBox.Show(this, "Set the path to pqc-cli.exe first.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (_schemeBox.SelectedItem is not string scheme || GetSelectedVariant() is not string variant || GetSelectedOperation() is not string op || GetSelectedEngine() is not string engine)
        {
            return;
        }

        var schemeArg = scheme == "ML-DSA" ? "ml-dsa" : "ml-kem";
        var opArg = op.ToLowerInvariant();
        var args = new List<string> { schemeArg, opArg, "--variant", variant, "--engine", engine };

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

            string folder = ResolveKeygenFolder(requestedFolder, variant, engine);
            try
            {
                Directory.CreateDirectory(folder);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Couldn't create '{folder}':\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                MessageBox.Show(this, "'Signing key (sk)' is required.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
                    "P-KAIDO",
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
                    MessageBox.Show(this, $"Couldn't save typed text:\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
        else if (op == "Encapsulate")
        {
            TextBox? pkBox = null, ctOutBox = null, ssOutBox = null;
            foreach (var (box, spec) in _currentFields)
            {
                switch (spec.ArgName)
                {
                    case "pk": pkBox = box; break;
                    case "ct-out": ctOutBox = box; break;
                    case "ss-out": ssOutBox = box; break;
                }
            }

            if (pkBox is null || string.IsNullOrWhiteSpace(pkBox.Text))
            {
                MessageBox.Show(this, "'Public key (pk)' is required.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            args.Add("--pk");
            args.Add(pkBox.Text);

            string ctOutPath = ResolveCiphertextPath(ctOutBox?.Text, variant);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ctOutPath)!);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Couldn't create output folder for '{ctOutPath}':\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            args.Add("--ct-out");
            args.Add(ctOutPath);

            if (ssOutBox is not null && !string.IsNullOrWhiteSpace(ssOutBox.Text))
            {
                args.Add("--ss-out");
                args.Add(ssOutBox.Text);
            }
        }
        else
        {
            foreach (var (box, spec) in _currentFields)
            {
                if (spec.Required && string.IsNullOrWhiteSpace(box.Text))
                {
                    MessageBox.Show(this, $"'{spec.Label}' is required.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
            MessageBox.Show(this, $"Failed to launch pqc-cli:\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
        _rows.Insert(0, new RunRow(DateTime.Now.ToString("HH:mm:ss"), scheme, op, variant, engine, ok, duration, summary, rawJson));
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

    private void BrowseAndInspectFile()
    {
        using var dialog = new OpenFileDialog { Filter = "All files|*.*", Multiselect = true };
        if (dialog.ShowDialog() == DialogResult.OK)
        {
            foreach (var path in dialog.FileNames)
            {
                InspectFile(path);
            }
        }
    }

    private void InspectFile(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Couldn't read '{path}':\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var json = JsonSerializer.Serialize(new
        {
            ok = true,
            op = "inspect",
            file = path,
            bytes = bytes.Length,
            hex = Convert.ToHexString(bytes).ToLowerInvariant(),
        });

        var row = new RunRow(
            DateTime.Now.ToString("HH:mm:ss"),
            "-",
            "Inspect",
            "-",
            "-",
            true,
            "-",
            $"{Path.GetFileName(path)} ({bytes.Length} bytes)",
            json);

        _rows.Insert(0, row);
        if (_grid.Rows.Count > 0)
        {
            _grid.ClearSelection();
            _grid.Rows[0].Selected = true;
        }
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

    private static string ResolveKeygenFolder(string? requestedFolder, string variant, string engine)
    {
        if (!string.IsNullOrWhiteSpace(requestedFolder))
        {
            return requestedFolder;
        }

        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        return Path.Combine(FindRepoRoot(), "keys", $"{stamp}_{variant}_{engine}");
    }

    private static string ResolveCiphertextPath(string? requestedPath, string variant)
    {
        if (!string.IsNullOrWhiteSpace(requestedPath))
        {
            return requestedPath;
        }

        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        return Path.Combine(FindRepoRoot(), "keys", $"{stamp}_{variant}-ct.bin");
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

    // Applies the palette to one control based on its runtime type. Called both for the static
    // control tree (via ThemeTree) and at each dynamic control's creation site (scheme/operation
    // change rebuilds radio buttons and fields at runtime, so a one-time tree walk isn't enough).
    private static void ThemeControl(Control control)
    {
        switch (control)
        {
            case Button button:
                button.FlatStyle = FlatStyle.Flat;
                button.BackColor = PanelColor;
                button.ForeColor = TextColor;
                button.FlatAppearance.BorderColor = BorderColor;
                button.FlatAppearance.MouseOverBackColor = BorderColor;
                break;
            case TextBox textBox:
                textBox.BackColor = InputBgColor;
                textBox.ForeColor = TextColor;
                textBox.BorderStyle = BorderStyle.FixedSingle;
                break;
            case ComboBox comboBox:
                comboBox.FlatStyle = FlatStyle.Flat;
                comboBox.BackColor = InputBgColor;
                comboBox.ForeColor = TextColor;
                break;
            case RadioButton radioButton:
                radioButton.ForeColor = TextColor;
                radioButton.BackColor = Color.Transparent;
                break;
            case Label label:
                label.ForeColor = TextColor;
                break;
            case DataGridView:
                break; // themed separately in the constructor — needs header/cell style, not just colors
            default:
                control.BackColor = BgColor;
                control.ForeColor = TextColor;
                break;
        }
    }

    private static void ThemeTree(Control root)
    {
        foreach (Control child in root.Controls)
        {
            ThemeControl(child);
            if (child.HasChildren)
            {
                ThemeTree(child);
            }
        }
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
