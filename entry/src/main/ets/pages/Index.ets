import { common } from '@kit.AbilityKit';
import { Constants } from '../common/Constants';
import { LogEntry, Logger, LogLevel } from '../common/Logger';
import { AuthConfig } from '../auth/AuthConfig';
import { AuthTransport } from '../auth/AuthTransport';
import { HttpAuthTransport } from '../auth/HttpAuthTransport';
import { MockAuthTransport } from '../auth/MockAuthTransport';
import { ServiceAccountAuth, STEP_NAMES, StepId, StepReport, StepStatus } from '../auth/ServiceAccountAuth';
import { JwtParts } from '../jwt/JwtBuilder';

@Entry
@Component
struct Index {
  @State steps: StepReport[] = STEP_NAMES.map((name: string, index: number) => new StepReport(index, name));
  @State jwtHeader: string = '';
  @State jwtPayload: string = '';
  @State jwtSignature: string = '';
  @State jwtExpiresAt: number = 0;
  @State tokenExpiresAt: number = 0;
  @State apiStatus: string = '';
  @State busy: boolean = false;
  @State useMock: boolean = true;
  @State hasServer: boolean = false;
  @State serverName: string = '';
  @State nowSeconds: number = Math.floor(Date.now() / 1000);
  @State logs: LogEntry[] = [];

  private config: AuthConfig = new AuthConfig();
  private auth?: ServiceAccountAuth;
  private mockTransport?: MockAuthTransport;
  private httpTransport?: HttpAuthTransport;
  private tickerId: number = -1;

  aboutToAppear(): void {
    const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
    try {
      this.config = AuthConfig.load(context);
    } catch (err) {
      this.addLog(`config.json could not be read: ${JSON.stringify(err)}`, LogLevel.ERROR);
    }
    this.hasServer = this.config.hasServer();
    this.useMock = !this.hasServer;
    this.mockTransport = new MockAuthTransport(context, this.config);
    this.httpTransport = new HttpAuthTransport(this.config);
    const transport = this.currentTransport();
    this.serverName = transport.name();
    this.auth = new ServiceAccountAuth(context, this.config, transport, {
      onStep: (report: StepReport) => this.onStep(report),
      onJwt: (parts: JwtParts, expiresAt: number) => this.onJwt(parts, expiresAt),
      onToken: (expiresAt: number) => {
        this.tokenExpiresAt = expiresAt;
      },
      onLog: (message: string, level: LogLevel) => this.addLog(message, level)
    });
    this.addLog(`Server: ${this.serverName}`);
  }

  onPageShow(): void {
    this.tickerId = setInterval(() => {
      this.nowSeconds = Math.floor(Date.now() / 1000);
    }, 1000);
  }

  onPageHide(): void {
    if (this.tickerId !== -1) {
      clearInterval(this.tickerId);
      this.tickerId = -1;
    }
  }

  private currentTransport(): AuthTransport {
    return (this.useMock ? this.mockTransport : this.httpTransport) as AuthTransport;
  }

  // ---------- Actions ----------

  private async run(action: string, task: () => Promise<void>): Promise<void> {
    if (this.busy) {
      return;
    }
    this.busy = true;
    try {
      await task();
    } catch (err) {
      this.addLog(err instanceof Error ? err.message : `${action} failed: ${JSON.stringify(err)}`, LogLevel.ERROR);
    } finally {
      this.busy = false;
    }
  }

  private generate(): void {
    this.resetSteps();
    this.run('Generate JWT', async () => {
      await this.auth?.generateJwt();
      this.addLog('JWT generated and verified');
    });
  }

  private getToken(): void {
    this.run('Get token', async () => {
      await this.auth?.fetchToken();
      this.addLog('Access token received');
    });
  }

  private callApi(): void {
    this.run('Call API', async () => {
      const result = await this.auth?.callApi();
      if (result !== undefined) {
        this.apiStatus = `${result.code} · ${result.body.substring(0, 60)}`;
        this.addLog(`API: HTTP ${result.code}`, result.code === 200 ? LogLevel.INFO : LogLevel.WARN);
      }
    });
  }

  private onMockChange(isOn: boolean): void {
    this.useMock = isOn;
    const transport = this.currentTransport();
    this.auth?.setTransport(transport);
    this.serverName = transport.name();
    this.tokenExpiresAt = 0;
    this.apiStatus = '';
    this.addLog(`Server: ${this.serverName}`);
  }

  private onStep(report: StepReport): void {
    this.steps = this.steps.map((step: StepReport) => step.id === report.id ? report : step);
    if (report.status === StepStatus.FAILED) {
      this.addLog(`${report.name}: ${report.detail}`, LogLevel.ERROR);
    } else if (report.status === StepStatus.OK) {
      this.addLog(`${report.name}: ${report.ms} ms`);
    }
  }

  private onJwt(parts: JwtParts, expiresAt: number): void {
    this.jwtHeader = parts.header;
    this.jwtPayload = parts.payload;
    this.jwtSignature = parts.signature;
    this.jwtExpiresAt = expiresAt;
  }

  private resetSteps(): void {
    this.steps = STEP_NAMES.map((name: string, index: number) => new StepReport(index, name));
  }

  private addLog(message: string, level: LogLevel = LogLevel.INFO): void {
    const entry = Logger.log(message, level);
    this.logs = [entry, ...this.logs].slice(0, Constants.LOG_LIMIT);
  }

  // ---------- View helpers ----------

  private remaining(expiresAt: number): string {
    const seconds = expiresAt - this.nowSeconds;
    if (seconds <= 0) {
      return 'expired';
    }
    const minutes = Math.floor(seconds / 60);
    return `${minutes}:${(seconds % 60).toString().padStart(2, '0')}`;
  }

  private stepIcon(status: StepStatus): string {
    switch (status) {
      case StepStatus.OK:
        return '✓';
      case StepStatus.FAILED:
        return '✗';
      case StepStatus.RUNNING:
        return '…';
      default:
        return '·';
    }
  }

  private stepColor(status: StepStatus): ResourceColor {
    switch (status) {
      case StepStatus.OK:
        return $r('app.color.success');
      case StepStatus.FAILED:
        return $r('app.color.error');
      case StepStatus.RUNNING:
        return $r('app.color.accent');
      default:
        return $r('app.color.neutral');
    }
  }

  private logColor(level: LogLevel): ResourceColor {
    switch (level) {
      case LogLevel.ERROR:
        return $r('app.color.error');
      case LogLevel.WARN:
        return $r('app.color.warning');
      default:
        return '#AEAEB2';
    }
  }

  // ---------- Layout ----------

  @Builder
  actionButton(label: Resource, color: ResourceColor, onTap: () => void) {
    Button(label)
      .width('70%')
      .height(42)
      .fontSize(15)
      .backgroundColor(color)
      .enabled(!this.busy)
      .onClick(onTap)
  }

  build() {
    Scroll() {
      Column({ space: 6 }) {
        Text($r('app.string.title'))
          .fontSize(18)
          .fontWeight(FontWeight.Medium)
          .fontColor(Color.White)
        Text(`Server: ${this.serverName}`)
          .width('76%')
          .fontSize(11)
          .fontColor(this.useMock ? $r('app.color.warning') : $r('app.color.neutral'))
          .textAlign(TextAlign.Center)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })

        this.actionButton($r('app.string.btn_generate'), $r('app.color.accent'), () => this.generate())
        this.actionButton($r('app.string.btn_token'), $r('app.color.card'), () => this.getToken())
        this.actionButton($r('app.string.btn_api'), $r('app.color.card'), () => this.callApi())

        if (this.jwtHeader.length > 0) {
          Text() {
            Span(this.jwtHeader).fontColor('#64D2FF')
            Span('.').fontColor(Color.White)
            Span(this.jwtPayload).fontColor('#30D158')
            Span('.').fontColor(Color.White)
            Span(this.jwtSignature).fontColor('#FF9F0A')
          }
          .width('80%')
          .fontSize(10)
          .maxLines(6)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .wordBreak(WordBreak.BREAK_ALL)

          Text(`JWT exp in ${this.remaining(this.jwtExpiresAt)}`)
            .fontSize(12)
            .fontColor('#C7C7CC')
        }
        if (this.tokenExpiresAt > 0) {
          Text(`Access token · ${this.remaining(this.tokenExpiresAt)}`)
            .fontSize(12)
            .fontColor(this.tokenExpiresAt > this.nowSeconds ? $r('app.color.success') : $r('app.color.warning'))
        }
        if (this.apiStatus.length > 0) {
          Text(`API ${this.apiStatus}`)
            .width('76%')
            .fontSize(12)
            .fontColor(Color.White)
            .textAlign(TextAlign.Center)
        }

        Text($r('app.string.steps'))
          .fontSize(13)
          .fontColor($r('app.color.neutral'))
          .margin({ top: 6 })
        ForEach(this.steps, (step: StepReport) => {
          Row({ space: 6 }) {
            Text(this.stepIcon(step.status))
              .width(14)
              .fontSize(13)
              .fontColor(this.stepColor(step.status))
            Column() {
              Text(step.name)
                .fontSize(13)
                .fontColor(Color.White)
              if (step.detail.length > 0) {
                Text(step.detail)
                  .fontSize(10)
                  .fontColor(this.stepColor(step.status))
                  .maxLines(2)
                  .textOverflow({ overflow: TextOverflow.Ellipsis })
              }
            }
            .alignItems(HorizontalAlign.Start)
            .layoutWeight(1)
            Text(step.status === StepStatus.OK || step.status === StepStatus.FAILED ? `${step.ms} ms` : '')
              .fontSize(11)
              .fontColor($r('app.color.neutral'))
          }
          .width('78%')
        }, (step: StepReport) => `${step.id}-${step.status}-${step.ms}`)

        Row() {
          Text($r('app.string.local_mock'))
            .fontSize(14)
            .fontColor(this.hasServer ? Color.White : $r('app.color.neutral'))
            .layoutWeight(1)
          Toggle({ type: ToggleType.Switch, isOn: this.useMock })
            .selectedColor($r('app.color.success'))
            .enabled(this.hasServer && !this.busy)
            .onChange((isOn: boolean) => this.onMockChange(isOn))
        }
        .width('78%')
        .height(40)

        Text($r('app.string.test_key_note'))
          .width('76%')
          .fontSize(11)
          .fontColor($r('app.color.warning'))
          .textAlign(TextAlign.Center)

        Text($r('app.string.event_log'))
          .fontSize(13)
          .fontColor($r('app.color.neutral'))
          .margin({ top: 6 })
        ForEach(this.logs, (entry: LogEntry) => {
          Text(`${entry.time}  ${entry.message}`)
            .width('76%')
            .fontSize(11)
            .fontColor(this.logColor(entry.level))
        }, (entry: LogEntry) => entry.id.toString())
      }
      .width('100%')
      .padding({ top: 40, bottom: 56 })
    }
    .width('100%')
    .height('100%')
    .scrollBar(BarState.Off)
    .backgroundColor(Color.Black)
  }
}
