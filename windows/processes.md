# فحص العمليات قيد التشغيل

يجب أن يحتوي الكمبيوتر المصاب ببرمجية التجسس على بعض العمليات الضارة التي تعمل في جميع الأوقات ومراقبة النظام وجمع البيانات ليتم نقلها إلى [خادم القيادة والتحكم](https://securitywithoutborders.org/resources/digital-security-glossary.html#cnc) الخاص بالمهاجمين. لذلك هناك خطوة أخرى في فحص جهاز كمبيوتر يعمل بنظام ويندوز مشتبه بإصابته وهي استخراج قائمة العمليات الجارية ومعرفة ما إذا كان أي منها يعرض خصائص مشبوهة.

ويتوفر عدد من الأدوات المتاحة للقيام بذلك.

**تحذير:** قد تكون برمجيات التجسس الأكثر تطورًا قادرة على التهرب من هذه الأداة إما عن طريق إخفاء إدخالاتها الخاصة من الشجرة أو ربما عن طريق الإنهاء الفوري إذا لاحظت إطلاق أي من هذه الأدوات، ونقدم في هذا الدليل بعض المنهجية والاقتراحات الأولية لإجراء تقييم أولي. ليست قائمة العمليات النظيفة بالضرورة ضمانًا لنظام نظيف.

قبل المتابعة بإجراء الفحص يُنصح بإغلاق جميع تطبيقات التشغيل الظاهرة من أجل تقليل مخرجات الأدوات التي سيتم تشغيلها إلى الحد الأدنى.

## أداة بروسيس إكسبلورر (Process Explorer)

أداة [بروسيس إكسبلورر](https://technet.microsoft.com/en-us/sysinternals/processexplorer.aspx) هي أداة أخرى من مجموعة [سيسينترنال](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) من مايكروسوفت وتسرد جميع العمليات التي تعمل على النظام ضمن شجرة:

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-f0108df27a21986070ac60515d9df349de303d85%252Fprocexp.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=3d23c6c0&sv=1)

تشبه نوعًا ما منهجية فحص العمليات قيد التشغيل المشبوهة ما وصفناه في قسم [فحص البرامج التي تبدأ مع تمهيد تشغيل الكمبيوتر](https://pellaeon.gitbook.io/mobile-forensics/windows/autoruns).

### 1\. تحقق من التوقيع الرقمي للصور

على غرار أتورانز تسمح أداة بروسيس إكسبلورر أيضًا بالتحقق من التواقيع الرقمية للتطبيقات قيد التشغيل بالنقر على _Options (خيارات)_ وتمكين "_التحقق من التواقيع الرقمية للصور (Verify Image Signatures)_". تنطبق ذات الاعتبارات والتحذيرات التي وصفناها في القسم [السابق](https://pellaeon.gitbook.io/mobile-forensics/windows/autoruns) هنا أيضًا، ولكنه إلى حد أهم في العمليات قيد التشغيل لأن حقيقة وجود توقيع رقمي لعملية التطبيق لا تعني بالضرورة أنها آمنة. غالبًا ما تستخدم البرمجيات الضارة تقنيات مثل[Process Hollowing (تجويف العملية)](https://attack.mitre.org/techniques/T1093/) أو [DLL Sideloading](https://attack.mitre.org/techniques/T1073/) لأجل تنفيذ التعليمات البرمجية ضمن سياق تطبيق سليم ويتمتع بتوقيع رقمي من أجل إحباط محاولات الكشف.

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-336c670160cdb617377ae14d19709b85cf666adb%252Fprocexp2.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=19d06913&sv=1)

### 2\. ابحث عن البرمجيات النصية

غالبًا ما يستفيد المهاجمون هذه الأيام من قدرات البرمجة النصية لنظام مايكروسوفت ويندوز مثل باور شيل (PowerShell) وويندوز سكريبت هوست (Windows Script Host) بسبب مرونتها وحتى القدرة على تجنب الكشف، ويشاع استخدام محركات البرمجة النصية هذه من قبل عملاء المؤسسات لأتمتة تكوينات الأنظمة الداخلية. من غير الشائع رؤية تطبيقات مستهلك تستخدمها لذلك يجب إجراء فحوص إضافية على أي عمليات ذات صلة قيد التشغيل.

عادة ما تسمى هذه العمليات `powershell.exe` أو `wscript.exe`.

فيما يلي مثال من بروسيس إكسبلورر يعرض برنامج نصي على باور شيل ضارًا يعمل بشكل واضح على النظام:

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-6ced6b88a74da288d7dcf06deaf8e2efeaa1cfdd%252Fprocexp_powershell.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=44ed3e12&sv=1)

يُظهر عند تمرير مؤشر فوق اسم العملية وسيطات سطر الأوامر التي تظهر بوضوح أن البرنامج النصي يحاول تنزيل وتنفيذ بعض التعليمات البرمجية الإضافية، ويلحظ أيضًا استخدام أحرف صغيرة وكبيرة مختلفة مثل "doWnLoAdfile " وتُعدّ هذه خدعة بسيطة جدًا يستخدمها المهاجمون للتهرب من أنماط الكشف الأساسية أيضًا لدى برمجيات الأمان.

### 3\. ابحث عن ملفات DLL قيد التشغيل

تأتي البرمجيات الضارة أحيانًا أيضًا في شكل [DLL (مكتبة ارتباطات ديناميكية)](https://support.microsoft.com/en-us/help/815065/what-is-a-dll) والتي - على عكس التطبيق المستقل (بمعنى آخر ملف `exe.`) - يجب تشغيلها بواسطة أداة تحميل. يوفر وويندوز بعض البرامج لتشغيل ملفات DLL، عادةً مثل `regsvr32.exe` و`rundll32.exe` التي تحصل على توقيعها من مايكروسوفت.

ابحث عن أي عمليات تستخدمها قيد التشغيل وحاول تحديد ملف DLL التي تنفذه. على سبيل المثال في لقطة الشاشة أدناه يمكننا رؤية نظام وويندوز مصاب يشغل ملف DLL ضار موجود في `C:\Users\<Username>\AppData\` باستخدام `regsvr32.exe`.

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-77501511fea7a2da3a8870af30bba3c415e66722%252Fprocexp_regsvr.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=7627dd44&sv=1)

### 4\. ابحث عن عمليات التطبيقات التي يجب أن تكون مرئية

من بين التقنيات العديدة التي غالبًا ما يستخدمها المهاجمون توجد طريقة تسمى [Process Hollowing (تجويف العملية)،](https://attack.mitre.org/techniques/T1093/) وتتمثل في تشغيل تطبيق سليم (مثل إنترنت اكسبلورر (Internet Explorer) أو جوجل كروم (Google Chrome)) وإفراغ ذاكرته واستبداله بشفرة ضارة يتم تنفيذها بعدها. عادة يتم ذلك لإخفاء التعليمات البرمجية الضارة وجعله يبدو وكأنه تطبيق سليم (يكون بعدها مجرد غلاف فارغ)، وكذلك للتهرب من تطبيقات جدار الحماية وربما التهرب من بعض المنتجات الأمنية الأخرى.

على سبيل المثال إذا شاهدت عملية `iexplore.exe` قيد التشغيل مع عدم وجود هناك نافذة إنترنت اكسبلورر مفتوحة يجب أن تعتبر أن هذه علامة مثيرة للقلق.

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-e61a3b5b2bf95a25b08b0ed7326c819469edb743%252Fprocexp_iexplore.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=e5495bfe&sv=1)

### اختياري: 5\. فحص البرامج على فيروس توتال (VirusTotal)

على غرار قسم [أتورانز](https://pellaeon.gitbook.io/mobile-forensics/windows/autoruns)، يقدم بروسيس إكسبلورر أيضًا إمكانية فحص العمليات قيد التشغيل على فيروس توتال من خلال فحص شفرة التجزئة التشفيرية للملفات القابلة للتنفيذ المحددة. يمكن تمكين ذلك بالنقر على _Options (خيارات)_ \\> _VirusTotal.com_ وتفعيل _Check VirusTotal.com_.

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-48c7bfe3489cc86f9011fa6ce81efbc4742d22c8%252Fprocexp3.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=753cad4b&sv=1)

**يرجى الانتباه:** تنطبق الاعتبارات والتحذيرات الموضحة في القسم [السابق ](https://pellaeon.gitbook.io/mobile-forensics/windows/autoruns) هنا أيضًا، لذا تأكد من قراءتها قبل المتابعة.

## أداة كراود إنسبكت (CrowdInspect)

تُعدّ أداة [كراود إنسبكت](https://www.crowdstrike.com/resources/community-tools/crowdinspect-tool/) أداة من إنتاج شركة الأمن الأمريكية كراود سترايك، وتشبه إلى حد كبير بروسيس إكسبلورر ولكن تتمتع ببعض المزايا الإضافية. في البداية تميل المعلومات التي تقدمها إلى أن تكون أكثر اختصارًا، وثانيًا لا تُظهر العمليات قيد التشغيل حاليًا فحسب بل يمكنها أيضًا إظهار العمليات التي انتهت منذ تشغيل الأداة (والتي ربما تكون قد فاتتك لأنه جرى تنفيذها بسرعة كبيرة جدًا). وأخيرًا تقوم بإجراء عدد أكبر من عمليات الفحص التي لا يدعمها بروسيس إكسبلورر حاليًا.

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-1ab9814cd2e5e2fc810c6b973dc84e0424046a00%252Fcrowdinspect.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=5013be1f&sv=1)

### التحقق من وجود أي حقن في العمليات

ربما تكون الميزة الأكثر إثارة للاهتمام التي تقدمها كراود إنسبكت هي القدرة على التعرّف على أي [عمليات محقونة،](https://attack.mitre.org/techniques/T1055/) حيث يُعدّ حقن العمليات فئة تقنيات التي يكون هدفها تشغيل التعليمات البرمجية الضارة في سياق تطبيق منفصل وسليم بشكل عام (مثل `explorer.exe`). غالبًا ما يستخدم مؤلفو البرمجيات الضارة حقن العمليات من أجل الحصول على امتيازات إضافية على النظام أو على سبيل المثال لتجنب الكشف.

وستقوم كراود إنسبكت بتنبيهك تجاه أي عمليات حقن عن طريق عرض نقطة حمراء مرئية تحت عمود "_Inject (حقن)_". تعتبر العمليات المحقونة بشكل عام مؤشرًا قويًا جدًا على احتمال وجود أنشطة حقن على الكمبيوتر الذي تم اختباره.

![](https://pellaeon.gitbook.io/~gitbook/image?url=https%3A%2F%2F3800278430-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F0nYvTpYLyJhfHy1skKdP%252Fuploads%252Fgit-blob-0df9444d13cda112b776049ff601600ce78e8fe3%252Fcrowdinspect_injection.png%3Falt%3Dmedia&width=768&dpr=4&quality=100&sign=ccd4f3c9&sv=1)