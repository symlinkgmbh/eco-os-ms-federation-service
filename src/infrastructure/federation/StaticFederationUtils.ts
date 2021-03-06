/**
 * Copyright 2018-2020 Symlink GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */




export class StaticFederationUtils {
  public static buildKeyChunks(key: string): Array<string> {
    const chunks: Array<string> = [];
    const part = 250;
    let counter = 0;

    while (counter < key.length) {
      chunks.push(key.substr(counter, part));
      counter += part;
    }

    return chunks;
  }
}
